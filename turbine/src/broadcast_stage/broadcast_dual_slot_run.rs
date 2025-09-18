use {
    super::*,
    crate::cluster_nodes::ClusterNodesCache,
    crossbeam_channel::Sender,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shred, Shredder},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    std::{str::FromStr, sync::OnceLock},
};

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum DualSlotPartition {
    /// Specify both groups by pubkeys explicitly
    GroupPubkeys {
        group_a: Vec<Pubkey>,
        group_b: Vec<Pubkey>,
    },
}

#[derive(Clone, Debug)]
pub struct BroadcastDualSlotConfig {
    /// How to partition nodes into two groups for dual slot broadcasting
    pub partition: DualSlotPartition,
    /// If passed `Some(receiver)`, will signal all the dual slot broadcasts via the given receiver
    pub dual_slot_sender: Option<Sender<(Slot, Slot)>>, // (slot_a, slot_b)
}

/// 全局缓存结构，缓存槽98的shreds
#[derive(Default, Clone)]
struct GlobalAttackCache {
    cached_slot98_shreds: Option<Vec<Shred>>, // 缓存的槽98 shreds
}

/// 全局静态缓存实例
static GLOBAL_ATTACK_CACHE: OnceLock<Arc<Mutex<GlobalAttackCache>>> = OnceLock::new();

/// 获取全局缓存实例
fn get_global_cache() -> Arc<Mutex<GlobalAttackCache>> {
    GLOBAL_ATTACK_CACHE
        .get_or_init(|| Arc::new(Mutex::new(GlobalAttackCache::default())))
        .clone()
}

#[derive(Clone)]
pub(super) struct BroadcastDualSlotRun {
    config: BroadcastDualSlotConfig,
    // 基于 StandardBroadcastRun 的基础字段
    slot: Slot,
    parent: Slot,
    chained_merkle_root: Hash,
    carryover_entry: Option<WorkingBankEntry>,
    next_shred_index: u32,
    next_code_index: u32,
    completed: bool,
    process_shreds_stats: ProcessShredsStats,
    shred_version: u16,
    cluster_nodes_cache: Arc<ClusterNodesCache<BroadcastStage>>,
    reed_solomon_cache: Arc<ReedSolomonCache>,

    // 双槽攻击相关字段（简化版）
    attacker_pubkey: Pubkey, // 攻击者公钥
}

impl BroadcastDualSlotRun {
    pub(super) fn new(shred_version: u16, config: BroadcastDualSlotConfig) -> Self {
        let cluster_nodes_cache = Arc::new(ClusterNodesCache::<BroadcastStage>::new(
            CLUSTER_NODES_CACHE_NUM_EPOCH_CAP,
            CLUSTER_NODES_CACHE_TTL,
        ));
        Self {
            config,
            slot: Slot::MAX,
            parent: Slot::MAX,
            chained_merkle_root: Hash::default(),
            carryover_entry: None,
            next_shred_index: 0,
            next_code_index: 0,
            completed: true,
            process_shreds_stats: ProcessShredsStats::default(),
            shred_version,
            cluster_nodes_cache,
            reed_solomon_cache: Arc::<ReedSolomonCache>::default(),

            // 双槽攻击字段初始化
            attacker_pubkey: Pubkey::from_str("AqEWUK8pdsfY2CTrBQLGS8w8ndMeuFcDpCkFwWaicaLL")
                .unwrap(),
        }
    }

    /// 检查是否应该拦截槽98和99
    fn should_intercept_slot(&mut self, slot: Slot, keypair: &Keypair) -> (bool, bool) {
        // 只有攻击者节点才进行拦截
        if keypair.pubkey() != self.attacker_pubkey {
            return (false, false);
        }

        // 写死：只处理槽98和99
        if slot == 98 {
            info!("🎯 拦截槽98（固定双槽攻击目标）");
            return (true, false); // (拦截, 是否为第99槽)
        } else if slot == 99 {
            info!("🎯 拦截槽99（固定双槽攻击目标）");
            return (true, true); // (拦截, 是否为第99槽)
        }

        (false, false)
    }
}

impl BroadcastRun for BroadcastDualSlotRun {
    fn run(
        &mut self,
        keypair: &Keypair,
        blockstore: &Blockstore,
        receiver: &Receiver<WorkingBankEntry>,
        socket_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
        blockstore_sender: &Sender<(Arc<Vec<Shred>>, Option<BroadcastShredBatchInfo>)>,
    ) -> Result<()> {
        // 1) 接收槽数据
        let receive_results = broadcast_utils::recv_slot_entries(
            receiver,
            &mut self.carryover_entry,
            &mut self.process_shreds_stats,
        )?;
        let bank = receive_results.bank.clone();
        let last_tick_height = receive_results.last_tick_height;

        // 2) 检查是否是新槽
        if bank.slot() != self.slot {
            self.slot = bank.slot();
            self.parent = bank.parent().unwrap().slot();
            self.chained_merkle_root = broadcast_utils::get_chained_merkle_root_from_parent(
                bank.slot(),
                bank.parent_slot(),
                blockstore,
            )
            .unwrap();
            self.next_shred_index = 0;
            self.next_code_index = 0;
            self.completed = false;

            info!("🆕 新槽{}开始处理", bank.slot());
        }

        if receive_results.entries.is_empty() {
            return Ok(());
        }

        // 3) 创建shreds
        let shredder = Shredder::new(
            bank.slot(),
            bank.parent().unwrap().slot(),
            (bank.tick_height() % bank.ticks_per_slot()) as u8,
            self.shred_version,
        )
        .expect("Expected to create a new shredder");

        let (data_shreds, coding_shreds) = shredder.entries_to_shreds(
            keypair,
            &receive_results.entries,
            last_tick_height == bank.max_tick_height(),
            Some(self.chained_merkle_root),
            self.next_shred_index,
            self.next_code_index,
            true, // merkle_variant
            &self.reed_solomon_cache,
            &mut self.process_shreds_stats,
        );

        // 更新状态
        if let Some(shred) = data_shreds.iter().max_by_key(|shred| shred.index()) {
            self.chained_merkle_root = shred.merkle_root().unwrap();
        }
        self.next_shred_index += data_shreds.len() as u32;
        if let Some(index) = coding_shreds.iter().map(Shred::index).max() {
            self.next_code_index = index + 1;
        }

        // 5) 正常发送到blockstore和socket（transmit会处理拦截）
        let data_shreds = Arc::new(data_shreds);
        blockstore_sender.send((data_shreds.clone(), None))?;
        socket_sender.send((data_shreds, None))?;

        Ok(())
    }

    fn transmit(
        &mut self,
        receiver: &TransmitReceiver,
        cluster_info: &ClusterInfo,
        sock: &UdpSocket,
        bank_forks: &RwLock<BankForks>,
        _quic_endpoint_sender: &AsyncSender<(SocketAddr, Bytes)>,
    ) -> Result<()> {
        let (shreds, _) = receiver.recv()?;
        if shreds.is_empty() {
            return Ok(());
        }

        let slot = shreds.first().unwrap().slot();

        // 🎯 核心逻辑：检查是否应该拦截这个槽的shreds
        let (should_intercept, is_fourth_slot) =
            self.should_intercept_slot(slot, &cluster_info.keypair());

        if should_intercept {
            let cache = get_global_cache();
            let mut global_cache = cache.lock().unwrap();

            if !is_fourth_slot {
                // 槽98：缓存shreds，等槽99
                info!("🎯 槽98缓存，等待槽99");
                global_cache.cached_slot98_shreds = Some(shreds.to_vec());
                return Ok(()); // 不发送，等槽99
            } else {
                // 槽99：触发双槽攻击
                info!("🎯 槽99到达，触发双槽攻击");
                // 继续发送流程，分组逻辑会处理槽99和缓存的槽98
            }
        }

        // 📡 发送到网络
        info!("📡 发送槽{}到网络 (共{}个shreds)", slot, shreds.len());

        let (root_bank, working_bank) = {
            let bank_forks = bank_forks.read().unwrap();
            (bank_forks.root_bank(), bank_forks.working_bank())
        };

        // 创建节点分组
        let (group_a, group_b): (HashSet<Pubkey>, HashSet<Pubkey>) = {
            let DualSlotPartition::GroupPubkeys { group_a, group_b } = &self.config.partition;
            (
                group_a.iter().cloned().collect(),
                group_b.iter().cloned().collect(),
            )
        };

        // 获取集群节点信息
        let cluster_nodes =
            self.cluster_nodes_cache
                .get(slot, &root_bank, &working_bank, cluster_info);
        let socket_addr_space = cluster_info.socket_addr_space();

        // 收集所有要发送的shreds（包括缓存的槽98）
        let mut all_shreds = shreds.to_vec();

        // 如果是槽99，加入缓存的槽98
        if slot == 99 {
            let cache = get_global_cache();
            let global_cache = cache.lock().unwrap();
            if let Some(cached_slot98) = &global_cache.cached_slot98_shreds {
                info!(
                    "📤 槽99同时发送缓存的槽98 ({}个shreds)",
                    cached_slot98.len()
                );
                all_shreds.extend(cached_slot98.clone());
            }
        }

        let packets: Vec<_> = all_shreds
            .iter()
            .filter_map(|shred| {
                let node = cluster_nodes.get_broadcast_peer(&shred.id())?;
                if !socket_addr_space.check(&node.tvu(Protocol::UDP)?) {
                    return None;
                }

                let node_pubkey = *node.pubkey();

                // 简化：直接基于槽号判断分组
                if shred.slot() == 99 {
                    // 槽99发给Group A
                    if group_a.contains(&node_pubkey) {
                        info!("🎯 {}发送槽99给Group A节点", shred.slot());
                        return Some(vec![(shred.payload(), node.tvu(Protocol::UDP)?)]);
                    } else {
                        return None; // 跳过发送给Group B节点
                    }
                } else if shred.slot() == 98 {
                    // 槽98发给Group B
                    if group_b.contains(&node_pubkey) {
                        info!("🎯 {}发送槽98给Group B节点", shred.slot());
                        return Some(vec![(shred.payload(), node.tvu(Protocol::UDP)?)]);
                    } else {
                        return None; // 跳过发送给Group A节点
                    }
                }

                // 普通shred：发送给所有节点
                info!("🎯 {}发送普通shred给所有节点", shred.slot());
                Some(vec![(shred.payload(), node.tvu(Protocol::UDP)?)])
            })
            .flatten()
            .collect();

        let result =
            batch_send(sock, packets).map_err(|SendPktsError::IoError(err, _)| Error::Io(err));

        // 双槽攻击逻辑已简化，不需要这部分检查

        result
    }

    fn record(&mut self, receiver: &RecordReceiver, blockstore: &Blockstore) -> Result<()> {
        let (all_shreds, _) = receiver.recv()?;
        blockstore
            .insert_shreds(all_shreds.to_vec(), None, true)
            .expect("Failed to insert shreds in blockstore");
        Ok(())
    }
}

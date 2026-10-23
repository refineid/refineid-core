use refineid_rapp::PairRecord;

fn main() {
    let expire_unless_recorded = |record: &PairRecord, now_ms: u64| record.idle_expired(now_ms);
    let _ = expire_unless_recorded;
}

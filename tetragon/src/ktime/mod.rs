use prost_types::Timestamp;
use std::time::{Duration, SystemTime};
use tracing::*;

fn decode_ktime(ktime: u64) -> Option<SystemTime> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let uptime_secs: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    let boottime = SystemTime::now() - Duration::from_secs_f64(uptime_secs);

    Some(boottime + Duration::from_nanos(ktime))
}

pub fn to_proto_opt(ktime: u64) -> Timestamp {
    match decode_ktime(ktime) {
        Some(decoded_time) => decoded_time.into(),
        None => {
            warn!("Failed to decode ktime: {}", ktime);
            SystemTime::now().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn test_proto_timestamp() -> anyhow::Result<()> {
        let ktime = 73119868981932;
        let proto_timestamp = to_proto_opt(ktime);
        println!("Protobuf Timestamp: {:?}", proto_timestamp);

        let datetime: DateTime<Utc> = SystemTime::try_from(proto_timestamp)?.into();
        println!("UTC: {}", datetime);

        Ok(())
    }
}

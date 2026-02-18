use pyo3::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};


static BLOCKED_COUNT: AtomicUsize = AtomicUsize::new(0);




fn inspect_packet(packet_id: u32, payload: String) -> bool {
    if payload.contains("DROP") || payload.contains("DELETE") || payload.contains("fuzz") {
        BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if packet_id == 0x666 || packet_id > 0x7FF {
        BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}






fn sanitize_command(command: String) -> Option<String> {



    if command.contains("MAX_THROTTLE") || command.contains("DROP") || command.contains("fuzz") {

        BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);

        return None; 
    }
    

    Some(command)
}



fn get_firewall_stats() -> usize {
    BLOCKED_COUNT.load(Ordering::Relaxed)
}



fn rust_can_firewall(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(inspect_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_firewall_stats, m)?)?;
    

    m.add_function(wrap_pyfunction!(sanitize_command, m)?)?; 
    
    Ok(())
}
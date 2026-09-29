//! Pure route-table parsing for the Windows client (compiled and unit-tested
//! on every platform; the Windows-only device code calls into it).

use std::net::Ipv4Addr;

/// One `route print` data row for the default route (dest 0.0.0.0, mask 0.0.0.0).
#[derive(Debug, Clone, PartialEq)]
pub struct DefaultRoute {
    /// None when the route is "On-link" (no IPv4 gateway column).
    pub gateway: Option<Ipv4Addr>,
    pub interface: Ipv4Addr,
    pub metric: u32,
}

/// Parse the default routes out of `route print -4` output. Locale
/// independent: only the numeric data rows are used
/// (`dest mask gateway interface metric`), never the translated headers.
pub fn parse_default_routes(route_print: &str) -> Vec<DefaultRoute> {
    let mut out = Vec::new();
    for line in route_print.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 5 || t[0] != "0.0.0.0" || t[1] != "0.0.0.0" {
            continue;
        }
        let Ok(interface) = t[t.len() - 2].parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(metric) = t[t.len() - 1].parse::<u32>() else {
            continue;
        };
        // Gateway is an IPv4 address, or a (possibly multi-word, localized)
        // "On-link" text.
        let gateway = t[2].parse::<Ipv4Addr>().ok();
        out.push(DefaultRoute {
            gateway,
            interface,
            metric,
        });
    }
    out
}

/// Pick the route the OS would use to reach `phys_ip` (the local address a
/// connection to the server leaves from), else the lowest-metric default.
pub fn choose_default_route(
    routes: &[DefaultRoute],
    phys_ip: Option<Ipv4Addr>,
) -> Option<DefaultRoute> {
    if let Some(ip) = phys_ip {
        if let Some(r) = routes
            .iter()
            .filter(|r| r.interface == ip)
            .min_by_key(|r| r.metric)
        {
            return Some(r.clone());
        }
    }
    routes.iter().min_by_key(|r| r.metric).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EN: &str = "\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
          0.0.0.0          0.0.0.0      10.0.0.1       10.0.0.7         45
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
";

    #[test]
    fn parses_default_routes_from_route_print() {
        let r = parse_default_routes(EN);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(r[0].interface, "192.168.1.50".parse::<Ipv4Addr>().unwrap());
        assert_eq!(r[0].metric, 25);
    }

    #[test]
    fn localized_onlink_gateway_is_not_a_parse_failure() {
        // Russian Windows prints "On-link" as "On-link" or "На канале";
        // multi-word text shifts columns, so only the last two are trusted.
        let ru = "          0.0.0.0          0.0.0.0    На канале      192.168.43.7     50\n";
        let r = parse_default_routes(ru);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].gateway, None);
        assert_eq!(r[0].interface, "192.168.43.7".parse::<Ipv4Addr>().unwrap());
        assert_eq!(r[0].metric, 50);
    }

    #[test]
    fn chooses_the_route_of_the_interface_that_reaches_the_server() {
        let routes = parse_default_routes(EN);
        // The OS would reach the server from 10.0.0.7 (higher metric row).
        let c = choose_default_route(&routes, Some("10.0.0.7".parse().unwrap())).unwrap();
        assert_eq!(c.gateway, Some("10.0.0.1".parse().unwrap()));
        // Unknown: lowest metric wins.
        let c = choose_default_route(&routes, None).unwrap();
        assert_eq!(c.metric, 25);
    }
}

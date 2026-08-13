//! nclr profile data package for the nclr-profiles crate.
//!
//! The profile TOMLs are embedded here so that the certified reference
//! profile ships with the source tree; the installer materializes them under
//! /usr/share/nclr/profiles/. Backends resolve profiles via
//! `nclr::profile::search_dirs` (NCLR_PROFILE_DIR /
//! /usr/share/nclr/profiles).

/// The sim controller family reference profile (certified C4 + SD vendor
/// read-only health).
pub const SIM_CONTROLLER_1: &str = include_str!("../../../profiles/sim-controller-1.toml");

/// All shipped profiles as (file name, content). Identification profiles are
/// read-only candidate selectors; only the sim profile is production trust.
pub const ALL: &[(&str, &str)] = &[
    ("sim-controller-1.toml", SIM_CONTROLLER_1),
    (
        "identify-alcor-ufd.toml",
        include_str!("../../../profiles/identify-alcor-ufd.toml"),
    ),
    (
        "identify-appotech-ufd.toml",
        include_str!("../../../profiles/identify-appotech-ufd.toml"),
    ),
    (
        "identify-chipsbank-ufd.toml",
        include_str!("../../../profiles/identify-chipsbank-ufd.toml"),
    ),
    (
        "identify-efortune-ufd.toml",
        include_str!("../../../profiles/identify-efortune-ufd.toml"),
    ),
    (
        "identify-hyperstone-ufd.toml",
        include_str!("../../../profiles/identify-hyperstone-ufd.toml"),
    ),
    (
        "identify-icreate-ufd.toml",
        include_str!("../../../profiles/identify-icreate-ufd.toml"),
    ),
    (
        "identify-innostor-ufd.toml",
        include_str!("../../../profiles/identify-innostor-ufd.toml"),
    ),
    (
        "identify-ite-ufd.toml",
        include_str!("../../../profiles/identify-ite-ufd.toml"),
    ),
    (
        "identify-netac-ufd.toml",
        include_str!("../../../profiles/identify-netac-ufd.toml"),
    ),
    (
        "identify-oti-ufd.toml",
        include_str!("../../../profiles/identify-oti-ufd.toml"),
    ),
    (
        "identify-phison-ufd.toml",
        include_str!("../../../profiles/identify-phison-ufd.toml"),
    ),
    (
        "identify-prolific-ufd.toml",
        include_str!("../../../profiles/identify-prolific-ufd.toml"),
    ),
    (
        "identify-sandisk-cruzer.toml",
        include_str!("../../../profiles/identify-sandisk-cruzer.toml"),
    ),
    (
        "identify-silicon-motion-ufd.toml",
        include_str!("../../../profiles/identify-silicon-motion-ufd.toml"),
    ),
    (
        "identify-skymedi-ufd.toml",
        include_str!("../../../profiles/identify-skymedi-ufd.toml"),
    ),
    (
        "identify-solid-state-system-ufd.toml",
        include_str!("../../../profiles/identify-solid-state-system-ufd.toml"),
    ),
    (
        "identify-usbest-ufd.toml",
        include_str!("../../../profiles/identify-usbest-ufd.toml"),
    ),
    (
        "identify-yeestor-ufd.toml",
        include_str!("../../../profiles/identify-yeestor-ufd.toml"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_profiles_validate() {
        // Every shipped profile must pass the same semantic validator used
        // by the installed CLI, not merely parse as TOML.
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in ALL {
            let path = dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            if name.starts_with("identify-") {
                nclr::profile::load_identify_profile(&path).unwrap();
            } else {
                nclr::profile::load(&path).unwrap();
            }
        }
    }

    #[test]
    fn sim_profile_is_production() {
        assert!(SIM_CONTROLLER_1.contains("trust = \"production\""));
        assert!(SIM_CONTROLLER_1.contains("certification = \"C4\""));
    }

    #[test]
    fn identification_profiles_are_packaged() {
        assert_eq!(
            ALL.iter()
                .filter(|(name, _)| name.starts_with("identify-"))
                .count(),
            18
        );
    }
}

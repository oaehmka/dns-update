#[cfg(test)]
mod tests {
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, MXRecord, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::infomaniak::InfomaniakProvider,
    };
    use std::time::Duration;

    // toggles for manual inspection of records
    const CREATE_RECORDS: bool = true;
    const UPDATE_RECORDS: bool = true;
    const DELETE_RECORDS: bool = true;

    fn test_records() -> Vec<(DnsRecord, DnsRecord, DnsRecordType)> {
        vec![
            (
                DnsRecord::A([1, 1, 1, 1].into()),
                DnsRecord::A([8, 8, 8, 8].into()),
                DnsRecordType::A,
            ),
            (
                DnsRecord::AAAA("2606:4700:4700::1111".parse().unwrap()),
                DnsRecord::AAAA("2001:4860:4860::8888".parse().unwrap()),
                DnsRecordType::AAAA,
            ),
            (
                DnsRecord::CNAME("create.example.com".to_string()),
                DnsRecord::CNAME("update.example.com".to_string()),
                DnsRecordType::CNAME,
            ),
            (
                DnsRecord::NS("ns1.example.com".to_string()),
                DnsRecord::NS("ns2.example.com".to_string()),
                DnsRecordType::NS,
            ),
            (
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail1.example.com".to_string(),
                }),
                DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "mail2.example.com".to_string(),
                }),
                DnsRecordType::MX,
            ),
            (
                DnsRecord::TXT("hello-infomaniak-create".to_string()),
                DnsRecord::TXT("hello-infomaniak-update".to_string()),
                DnsRecordType::TXT,
            ),
            (
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 443,
                    target: "sip1.example.com".to_string(),
                }),
                DnsRecord::SRV(SRVRecord {
                    priority: 20,
                    weight: 10,
                    port: 8443,
                    target: "sip2.example.com".to_string(),
                }),
                DnsRecordType::SRV,
            ),
            (
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: (0xA0..0xC0).collect(),
                }),
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: (0xC0..0xE0).collect(),
                }),
                DnsRecordType::TLSA,
            ),
            (
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsdecrypt.org".to_string()),
                    options: vec![],
                }),
                DnsRecordType::CAA,
            ),
        ]
    }

    #[tokio::test]
    #[ignore = "Requires Infomaniak API keys and domain configuration"]
    async fn integration_test_all_record_types() {
        let api_key = std::env::var("INFOMANIAK_API_KEY").unwrap_or_default();
        let domain = std::env::var("INFOMANIAK_DOMAIN").unwrap_or_default();
        let origin = std::env::var("INFOMANIAK_ORIGIN").unwrap_or_default();

        assert!(!api_key.is_empty(), "Please configure INFOMANIAK_API_KEY");
        assert!(!domain.is_empty(), "Please configure INFOMANIAK_DOMAIN");
        assert!(!origin.is_empty(), "Please configure INFOMANIAK_ORIGIN");

        let updater = DnsUpdater::new_infomaniak(api_key, Some(Duration::from_secs(30))).unwrap();

        for (create_record, update_record, record_type) in test_records() {
            let test_domain = match record_type {
                DnsRecordType::SRV => srv_domain(&domain, &record_type),
                _ => format!("{}-{}", record_type.as_str().to_ascii_lowercase(), domain),
            };

            if CREATE_RECORDS {
                let create_result = updater
                    .create(&test_domain, create_record.clone(), 300, &origin)
                    .await;

                assert!(
                    create_result.is_ok(),
                    "Failed to create {:?}: {:?}",
                    record_type,
                    create_result
                );
            }

            if UPDATE_RECORDS {
                let update_result = updater
                    .update(&test_domain, update_record, 300, &origin)
                    .await;

                assert!(
                    update_result.is_ok(),
                    "Failed to update {:?}: {:?}",
                    record_type,
                    update_result
                );
            }

            if DELETE_RECORDS {
                let delete_result = updater.delete(&test_domain, &origin, record_type).await;

                assert!(
                    delete_result.is_ok(),
                    "Failed to delete {:?}: {:?}",
                    record_type,
                    delete_result
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "Requires Infomaniak API keys and domain configuration"]
    async fn integration_test_duplicate_records() {
        let api_key = std::env::var("INFOMANIAK_API_KEY").unwrap_or_default();
        let domain = std::env::var("INFOMANIAK_DOMAIN").unwrap_or_default();
        let origin = std::env::var("INFOMANIAK_ORIGIN").unwrap_or_default();

        assert!(!api_key.is_empty(), "Please configure INFOMANIAK_API_KEY");
        assert!(!domain.is_empty(), "Please configure INFOMANIAK_DOMAIN");
        assert!(!origin.is_empty(), "Please configure INFOMANIAK_ORIGIN");

        let updater = DnsUpdater::new_infomaniak(api_key, Some(Duration::from_secs(30))).unwrap();

        if CREATE_RECORDS {
            let create_result = updater
                .create(
                    &domain,
                    DnsRecord::TXT("infomaniak-test-1".to_string()),
                    300,
                    &origin,
                )
                .await;
            assert!(
                create_result.is_ok(),
                "Failed to create first record: {:?}",
                create_result
            );

            let create_result = updater
                .create(
                    &domain,
                    DnsRecord::TXT("infomaniak-test-2".to_string()),
                    300,
                    &origin,
                )
                .await;
            assert!(
                create_result.is_ok(),
                "Failed to create second record: {:?}",
                create_result,
            );
        }

        if UPDATE_RECORDS {
            let update_result = updater
                .update(
                    &domain,
                    DnsRecord::TXT("infomaniak-test-3".to_string()),
                    300,
                    &origin,
                )
                .await;
            assert!(
                update_result.is_ok(),
                "Failed to update duplicate record: {:?}",
                update_result,
            );
        }
        if DELETE_RECORDS {
            let delete_result = updater.delete(&domain, &origin, DnsRecordType::TXT).await;
            assert!(
                delete_result.is_ok(),
                "Failed to delete first record: {:?}",
                delete_result,
            );
            let delete_result = updater.delete(&domain, &origin, DnsRecordType::TXT).await;
            assert!(
                delete_result.is_ok(),
                "Failed to delete second record: {:?}",
                delete_result,
            );
        }
    }

    #[tokio::test]
    #[ignore = "Requires Infomaniak API keys and domain configuration"]
    async fn integration_test_create_zone_level_record() {
        let api_key = std::env::var("INFOMANIAK_API_KEY").unwrap_or_default();
        let origin = std::env::var("INFOMANIAK_ORIGIN").unwrap_or_default();

        assert!(!api_key.is_empty(), "Please configure INFOMANIAK_API_KEY");
        assert!(!origin.is_empty(), "Please configure INFOMANIAK_ORIGIN");

        let updater = DnsUpdater::new_infomaniak(api_key, Some(Duration::from_secs(30))).unwrap();

        // let origin = "";

        if CREATE_RECORDS {
            let create_result = updater
                .create(
                    &origin,
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: (0xA0..0xC0).collect(),
                    }),
                    300,
                    &origin,
                )
                .await;

            assert!(
                create_result.is_ok(),
                "Failed to create zone-level TLSA record: {:?}",
                create_result
            );
        }

        if UPDATE_RECORDS {
            let update_result = updater
                .update(
                    &origin,
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: (0xC0..0xE0).collect(),
                    }),
                    300,
                    &origin,
                )
                .await;

            assert!(
                update_result.is_ok(),
                "Failed to update zone-level TLSA record: {:?}",
                update_result
            );
        }

        if DELETE_RECORDS {
            let delete_result = updater.delete(&origin, &origin, DnsRecordType::TLSA).await;

            assert!(
                delete_result.is_ok(),
                "Failed to delete zone-level TLSA record: {:?}",
                delete_result
            );
        }
    }

    #[test]
    fn provider_creation() {
        let provider =
            InfomaniakProvider::new("infomaniak-mock-api-key", Some(Duration::from_secs(1)));

        assert!(provider.is_ok());
    }

    #[test]
    fn dns_updater_creation() {
        let updater =
            DnsUpdater::new_infomaniak("infomaniak-mock-api-key", Some(Duration::from_secs(30)));

        assert!(
            matches!(updater, Ok(DnsUpdater::Infomaniak(..))),
            "Expected Infomaniak updater to provide an Infomaniak provider"
        );
    }

    fn srv_domain(base: &str, record_type: &DnsRecordType) -> String {
        let (label, rest) = base.split_once('.').unwrap_or((base, ""));

        let prefix = format!(
            "{}-{}._tcp",
            record_type.as_str().to_ascii_lowercase(),
            label
        );

        if rest.is_empty() {
            prefix
        } else {
            format!("{prefix}.{rest}")
        }
    }
}

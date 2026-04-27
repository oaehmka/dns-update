/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct InfomaniakProvider {
    client: HttpClientBuilder,
}

/// Infomaniak DNS provider implementation.
/// API documentation: <https://developer.infomaniak.com/docs/api>
///
/// Getting your API key: <https://manager.infomaniak.com/v3/ng/accounts/token/list>
/// API key permissions: `dns:read` and `dns:write` for the relevant domain(s)
///
/// Implemented using:
/// - [Store](https://developer.infomaniak.com/docs/api/post/2/zones/%7Bzone%7D/records)
/// - [Update](https://developer.infomaniak.com/docs/api/put/2/zones/%7Bzone%7D/records/%7Brecord%7D)
/// - [Delete](https://developer.infomaniak.com/docs/api/delete/2/zones/%7Bzone%7D/records/%7Brecord%7D)
///
/// and a helper function to retrieve existing records for update/delete operations:
/// - [List](https://developer.infomaniak.com/docs/api/get/2/zones/%7Bzone%7D/records)
impl InfomaniakProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(Self {
            client: HttpClientBuilder::default()
                .with_header("Authorization", format!("Bearer {}", api_key.as_ref()))
                .with_timeout(timeout),
        })
    }

    // ---
    // Library functions

    /// Create/Store a new DNS record.
    /// [Store](https://developer.infomaniak.com/docs/api/post/2/zones/%7Bzone%7D/records)
    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let source = strip_origin_from_name(&name, &origin, Some("."));
        let record_type = record.as_type().as_str().to_string();
        let target = record.to_infomaniak_target();

        let body = CreateRecordBody {
            source,
            target,
            ttl,
            r#type: record_type,
        };

        self.client
            .post(format!(
                "https://api.infomaniak.com/2/zones/{origin}/records"
            ))
            .with_body(&body)?
            .send::<InfomaniakApiResponse<serde_json::Value>>()
            .await?
            .into_result()
            .map(|_| ())
    }

    /// Update an existing DNS record.
    /// Infomaniak's API requires the record ID for update operation.
    /// This function first lists all records for the zone and matches
    /// the record by name and type to get the required ID.
    /// If multiple records with the same name and type exist, only the first one will be updated.
    /// [Update](https://developer.infomaniak.com/docs/api/put/2/zones/%7Bzone%7D/records/%7Brecord%7D)
    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let source = strip_origin_from_name(&name, &origin, Some("."));

        let records = self.get_zone_records(origin.as_str()).await?;
        let infomaniak_record = records
            .iter()
            .find(|r| r.source == source && r.record_type == record.as_type().as_str())
            .ok_or(Error::NotFound)?;

        let target = record.to_infomaniak_target();
        let body = UpdateRecordBody { target, ttl };

        self.client
            .put(format!(
                "https://api.infomaniak.com/2/zones/{origin}/records/{}",
                infomaniak_record.id
            ))
            .with_body(&body)?
            .send_with_retry::<InfomaniakApiResponse<serde_json::Value>>(3)
            .await?
            .into_result()
            .map(|_| ())
    }

    /// Delete an existing DNS record.
    /// Infomaniak's API requires the record ID for delete operation.
    /// This function first lists all records for the zone and matches
    /// the record by name and type to get the required ID.
    /// If multiple records with the same name and type exist, only the first one will be deleted.
    /// [Delete](https://developer.infomaniak.com/docs/api/delete/2/zones/%7Bzone%7D/records/%7Brecord%7D)
    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let source = strip_origin_from_name(&name, &origin, Some("."));

        let records = self.get_zone_records(origin.as_str()).await?;
        let record_id = records
            .iter()
            .find(|r| r.source == source && r.record_type == record.as_str())
            .map(|r| r.id)
            .ok_or(Error::NotFound)?;

        self.client
            .delete(format!(
                "https://api.infomaniak.com/2/zones/{origin}/records/{record_id}"
            ))
            .send::<InfomaniakApiResponse<serde_json::Value>>()
            .await?
            .into_result()
            .map(|_| ())
    }

    // ---
    // Utility functions

    /// [List](https://developer.infomaniak.com/docs/api/get/2/zones/%7Bzone%7D/records)
    async fn get_zone_records(
        &self,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<InfomaniakDnsRecord>> {
        let origin = origin.into_name();
        let domain = origin.as_ref();

        self.client
            .get(format!(
                "https://api.infomaniak.com/2/zones/{domain}/records"
            ))
            .send_with_retry::<InfomaniakRecordsList<InfomaniakDnsRecord>>(3)
            .await?
            .into_result()
    }
}

// -----------
// Local Structs, Traits and Implementations

trait InfomaniakFormat {
    fn to_infomaniak_target(&self) -> String;
}

impl InfomaniakFormat for DnsRecord {
    fn to_infomaniak_target(&self) -> String {
        match self {
            DnsRecord::A(ip) => ip.to_string(),
            DnsRecord::AAAA(ip) => ip.to_string(),
            DnsRecord::CNAME(name) | DnsRecord::NS(name) => name.clone(),
            DnsRecord::MX(mx) => mx.to_string(),
            DnsRecord::TXT(text) => text.to_string(),
            DnsRecord::SRV(srv) => srv.to_string(),
            DnsRecord::TLSA(tlsa) => tlsa.to_string(),
            DnsRecord::CAA(caa) => caa.to_string(),
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
struct InfomaniakApiResponse<T> {
    result: String,
    data: T,
}

impl<T> InfomaniakApiResponse<T> {
    fn into_result(self) -> crate::Result<T> {
        if self.result == "success" {
            Ok(self.data)
        } else {
            Err(Error::Api(format!(
                "Infomaniak API returned result={}",
                self.result
            )))
        }
    }
}

// -----------
// API Requests

#[derive(Serialize, Clone, Debug)]
struct CreateRecordBody {
    source: String,
    target: String,
    ttl: u32,
    #[serde(rename = "type")]
    r#type: String,
}

#[derive(Serialize, Clone, Debug)]
struct UpdateRecordBody {
    target: String,
    ttl: u32,
}

// -----------
// API Responses

#[derive(Deserialize, Clone, Debug)]
struct InfomaniakRecordsList<InfomaniakDnsRecord> {
    result: String,
    data: Vec<InfomaniakDnsRecord>,
    #[expect(dead_code)]
    total: Option<u32>,
    #[expect(dead_code)]
    page: Option<u32>,
    #[expect(dead_code)]
    pages: Option<u32>,
    #[expect(dead_code)]
    items_per_page: Option<u32>,
}

impl<T> InfomaniakRecordsList<T> {
    fn into_result(self) -> crate::Result<Vec<T>> {
        if self.result == "success" {
            Ok(self.data)
        } else {
            Err(Error::Api(format!(
                "Infomaniak API returned result={}",
                self.result
            )))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
struct InfomaniakDnsRecord {
    id: u32,
    source: String,
    source_idn: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    target: String,
    updated_at: u64,
    dyndns_id: Option<u32>,
    delegated_zone: Option<serde_json::Value>,
    description: Option<serde_json::Value>,
}

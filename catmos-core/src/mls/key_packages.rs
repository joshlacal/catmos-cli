use catbird_mls::KeyPackageResult;

use super::MlsManager;
use crate::error::Result;

impl MlsManager {
    /// Create a single key package for the given identity.
    pub fn create_key_package(&self, identity: &[u8]) -> Result<KeyPackageResult> {
        self.with_context(|ctx| ctx.create_key_package(identity.to_vec()))
    }

    /// Create multiple key packages in one batch.
    pub fn create_key_packages(
        &self,
        identity: &[u8],
        count: u32,
    ) -> Result<Vec<KeyPackageResult>> {
        let mut results = Vec::with_capacity(count as usize);
        for _ in 0..count {
            results.push(self.create_key_package(identity)?);
        }
        Ok(results)
    }
}

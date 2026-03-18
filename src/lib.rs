pub mod poseidon_constants;
pub mod fri;
pub use fri::*;

use crate::poseidon_constants::{POSEIDON_MDS_MATRIX_FLAT, POSEIDON_ROUND_CONSTANTS_FLAT};

#[repr(C)]
pub struct EngineContext {
    _private: [u8; 0],
}

#[link(name = "qingming", kind = "dylib")]
extern "C" {
    fn qingming_init_engine(num_streams: libc::c_int) -> *mut EngineContext;
    fn qingming_init_poseidon_constants(h_ark: *const u64, h_mds: *const u64) -> libc::c_int;
    fn qingming_execute_poseidon_batch_async(
        ctx: *mut EngineContext,
        stream_id: libc::c_int,
        in_data: *const u64,
        out_data: *mut u64,
        batch_size: libc::c_int,
    ) -> libc::c_int;
    fn qingming_build_merkle_tree_async(
        ctx: *mut EngineContext,
        stream_id: libc::c_int,
        in_leaves: *const u64,
        out_tree: *mut u64,
        num_leaves: libc::c_int,
    ) -> libc::c_int;
    fn qingming_execute_async(
        ctx: *mut EngineContext,
        stream_id: libc::c_int,
        in_data: *const u64,
        out_data: *mut u64,
    ) -> libc::c_int;
    fn qingming_execute_intt_async(
        ctx: *mut EngineContext,
        stream_id: libc::c_int,
        in_data: *const u64,
        out_data: *mut u64,
    ) -> libc::c_int;
    fn qingming_execute_coset_shift_async(
        ctx: *mut EngineContext,
        stream_id: libc::c_int,
        in_data: *const u64,
        out_data: *mut u64,
        shift_factor: u64,
    ) -> libc::c_int;
    fn qingming_sync_stream(ctx: *mut EngineContext, stream_id: libc::c_int) -> libc::c_int;
    fn qingming_destroy_engine(ctx: *mut EngineContext);
}

pub struct QingmingEngine {
    ctx: *mut EngineContext,
}

unsafe impl Send for QingmingEngine {}
unsafe impl Sync for QingmingEngine {}

impl QingmingEngine {
    pub fn new(num_streams: i32) -> Self {
        let ctx = unsafe { qingming_init_engine(num_streams) };
        assert!(!ctx.is_null());
        Self { ctx }
    }

    pub fn load_poseidon_constants(&self, ark: &[u64], mds: &[u64]) {
        assert_eq!(ark.len(), 360);
        assert_eq!(mds.len(), 144);
        let status = unsafe { qingming_init_poseidon_constants(ark.as_ptr(), mds.as_ptr()) };
        assert_eq!(status, 0);
    }

    pub fn load_real_poseidon_constants(&self) {
        self.load_poseidon_constants(&POSEIDON_ROUND_CONSTANTS_FLAT, &POSEIDON_MDS_MATRIX_FLAT);
    }

    pub fn poseidon_batch_async(
        &self,
        stream_id: i32,
        in_data: &[u64],
        out_data: &mut [u64],
        batch_size: i32,
    ) {
        assert_eq!(in_data.len(), (batch_size * 12) as usize);
        assert_eq!(out_data.len(), (batch_size * 12) as usize);
        let status = unsafe {
            qingming_execute_poseidon_batch_async(
                self.ctx,
                stream_id,
                in_data.as_ptr(),
                out_data.as_mut_ptr(),
                batch_size,
            )
        };
        assert_eq!(status, 0);
    }

    pub fn build_merkle_tree_async(
        &self,
        stream_id: i32,
        in_leaves: &[u64],
        out_tree: &mut [u64],
        num_leaves: i32,
    ) {
        assert!(num_leaves > 0 && (num_leaves as u32).is_power_of_two());
        assert_eq!(in_leaves.len(), (num_leaves * 4) as usize);
        assert_eq!(out_tree.len(), ((2 * num_leaves - 1) * 4) as usize);
        let status = unsafe {
            qingming_build_merkle_tree_async(
                self.ctx,
                stream_id,
                in_leaves.as_ptr(),
                out_tree.as_mut_ptr(),
                num_leaves,
            )
        };
        assert_eq!(status, 0);
    }

    pub fn ntt_async(&self, stream_id: i32, in_data: &[u64], out_data: &mut [u64]) {
        assert_eq!(in_data.len(), out_data.len());
        let status = unsafe {
            qingming_execute_async(self.ctx, stream_id, in_data.as_ptr(), out_data.as_mut_ptr())
        };
        assert_eq!(status, 0);
    }

    pub fn intt_async(&self, stream_id: i32, in_data: &[u64], out_data: &mut [u64]) {
        assert_eq!(in_data.len(), out_data.len());
        let status = unsafe {
            qingming_execute_intt_async(self.ctx, stream_id, in_data.as_ptr(), out_data.as_mut_ptr())
        };
        assert_eq!(status, 0);
    }

    pub fn coset_shift_async(
        &self,
        stream_id: i32,
        in_data: &[u64],
        out_data: &mut [u64],
        shift_factor: u64,
    ) {
        assert_eq!(in_data.len(), out_data.len());
        let status = unsafe {
            qingming_execute_coset_shift_async(
                self.ctx,
                stream_id,
                in_data.as_ptr(),
                out_data.as_mut_ptr(),
                shift_factor,
            )
        };
        assert_eq!(status, 0);
    }

    pub fn wait_stream(&self, stream_id: i32) {
        let status = unsafe { qingming_sync_stream(self.ctx, stream_id) };
        assert_eq!(status, 0);
    }
}

impl Drop for QingmingEngine {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                qingming_destroy_engine(self.ctx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::{Digest, FriConfig, FriProof, FriProver, FriVerifier};

    const N_SIZE: usize = 16_777_216;

    fn load_real_poseidon(engine: &QingmingEngine) {
        engine.load_real_poseidon_constants();
    }

    fn test_fri_config() -> FriConfig {
        FriConfig {
            num_queries: 3,
            final_codeword_size: 128,
            domain_generator: 7,
            domain_offset: 1,
        }
    }

    fn cpu_merkle_root_only(leaves: &[Digest]) -> Digest {
        assert!(!leaves.is_empty());
        assert!(leaves.len().is_power_of_two());

        let mut current = leaves.to_vec();

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for i in 0..(current.len() / 2) {
                next.push(crate::fri::poseidon_hash_pair(&current[2 * i], &current[2 * i + 1]));
            }
            current = next;
        }

        current[0]
    }

    fn run_fri_roundtrip(engine: &QingmingEngine, domain_size: usize) -> FriProof {
        let initial_codeword: Vec<u64> = (0..(domain_size * 4)).map(|x| x as u64).collect();
        let config = test_fri_config();
        let prover = FriProver::new(engine, config);
        prover.prove(0, &initial_codeword)
    }

    #[test]
    fn test_poseidon_batch() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let batch_size = 1024;
        let in_data = vec![1u64; batch_size * 12];
        let mut out_data = vec![0u64; batch_size * 12];

        engine.poseidon_batch_async(0, &in_data, &mut out_data, batch_size as i32);
        engine.wait_stream(0);

        assert_ne!(out_data[0], 0);
    }

    #[test]
    fn test_merkle_tree_pipeline_l0() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let num_leaves = 1024;
        let mut leaves = vec![0u64; num_leaves * 4];

        for i in 0..num_leaves {
            leaves[i * 4] = i as u64;
            leaves[i * 4 + 1] = (i * 2) as u64;
            leaves[i * 4 + 2] = (i * 3) as u64;
            leaves[i * 4 + 3] = (i * 4) as u64;
        }

        let total_nodes = 2 * num_leaves - 1;
        let mut tree_buffer = vec![0u64; total_nodes * 4];

        engine.build_merkle_tree_async(0, &leaves, &mut tree_buffer, num_leaves as i32);
        engine.wait_stream(0);

        let root_offset = (total_nodes - 1) * 4;
        let root_digest = &tree_buffer[root_offset..root_offset + 4];

        assert_ne!(root_digest[0], 0);
        assert_ne!(root_digest[1], 0);
    }

    #[test]
    fn test_merkle_root_cpu_gpu_consistency() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let num_leaves = 1024usize;
        let mut leaves_flat = vec![0u64; num_leaves * 4];

        for i in 0..num_leaves {
            leaves_flat[i * 4] = i as u64 + 11;
            leaves_flat[i * 4 + 1] = (i as u64).wrapping_mul(3).wrapping_add(7);
            leaves_flat[i * 4 + 2] = (i as u64).wrapping_mul(5).wrapping_add(13);
            leaves_flat[i * 4 + 3] = (i as u64).wrapping_mul(7).wrapping_add(17);
        }

        let total_nodes = 2 * num_leaves - 1;
        let mut gpu_tree_flat = vec![0u64; total_nodes * 4];

        engine.build_merkle_tree_async(0, &leaves_flat, &mut gpu_tree_flat, num_leaves as i32);
        engine.wait_stream(0);

        let gpu_root_offset = (total_nodes - 1) * 4;
        let gpu_root = [
            gpu_tree_flat[gpu_root_offset],
            gpu_tree_flat[gpu_root_offset + 1],
            gpu_tree_flat[gpu_root_offset + 2],
            gpu_tree_flat[gpu_root_offset + 3],
        ];

        let cpu_leaves: Vec<Digest> = leaves_flat
            .chunks_exact(4)
            .map(|c| [c[0], c[1], c[2], c[3]])
            .collect();

        let cpu_root = cpu_merkle_root_only(&cpu_leaves);

        assert_eq!(gpu_root, cpu_root, "CPU/GPU Merkle root mismatch");
    }

    #[test]
    fn test_ntt_intt() {
        let engine = QingmingEngine::new(1);
        let in_data = vec![1u64; N_SIZE];
        let mut out_data = vec![0u64; N_SIZE];
        let mut recovered_data = vec![0u64; N_SIZE];

        engine.ntt_async(0, &in_data, &mut out_data);
        engine.wait_stream(0);
        assert_ne!(out_data[0], 0);

        engine.intt_async(0, &out_data, &mut recovered_data);
        engine.wait_stream(0);
        assert_ne!(recovered_data[0], 0);
    }

    #[test]
    fn test_coset_shift() {
        let engine = QingmingEngine::new(1);
        let in_data = vec![2u64; N_SIZE];
        let mut out_data = vec![0u64; N_SIZE];

        engine.coset_shift_async(0, &in_data, &mut out_data, 7);
        engine.wait_stream(0);

        assert_ne!(out_data[0], 0);
        assert_ne!(out_data[1], 0);
    }

    #[test]
    fn test_fri_prove_verify_end_to_end() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let domain_size = 1024usize;
        let initial_codeword: Vec<u64> = (0..(domain_size * 4)).map(|x| x as u64).collect();

        let config = test_fri_config();
        let prover = FriProver::new(&engine, config.clone());
        let proof = prover.prove(0, &initial_codeword);

        assert_eq!(proof.config.num_queries, config.num_queries);
        assert_eq!(proof.final_codeword.len(), config.final_codeword_size);

        let verifier = FriVerifier::new(config);
        let is_valid = verifier.verify(&proof);

        assert!(is_valid, "FRI prove/verify end-to-end failed");
    }

    #[test]
    fn test_fri_tampered_root_fails() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let domain_size = 1024usize;
        let initial_codeword: Vec<u64> = (0..(domain_size * 4)).map(|x| x as u64).collect();

        let config = test_fri_config();
        let prover = FriProver::new(&engine, config.clone());
        let mut proof = prover.prove(0, &initial_codeword);

        proof.roots[0][0] ^= 1234567;

        let verifier = FriVerifier::new(config);
        let is_valid = verifier.verify(&proof);

        assert!(!is_valid, "tampered root should fail");
    }

    #[test]
    fn test_fri_tampered_opening_fails() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let domain_size = 1024usize;
        let initial_codeword: Vec<u64> = (0..(domain_size * 4)).map(|x| x as u64).collect();

        let config = test_fri_config();
        let prover = FriProver::new(&engine, config.clone());
        let mut proof = prover.prove(0, &initial_codeword);

        proof.queries[0].layers[0].x_eval[0] ^= 42;

        let verifier = FriVerifier::new(config);
        let is_valid = verifier.verify(&proof);

        assert!(!is_valid, "tampered opening should fail");
    }

    #[test]
    fn test_fri_prove_verify_end_to_end_twice() {
        let engine = QingmingEngine::new(1);
        load_real_poseidon(&engine);

        let proof1 = run_fri_roundtrip(&engine, 1024);
        let proof2 = run_fri_roundtrip(&engine, 1024);

        let verifier = FriVerifier::new(test_fri_config());

        assert!(verifier.verify(&proof1));
        assert!(verifier.verify(&proof2));
    }
}

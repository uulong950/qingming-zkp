use crate::poseidon_constants::{POSEIDON_MDS_MATRIX, POSEIDON_ROUND_CONSTANTS};
use crate::QingmingEngine;

pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;
pub const POSEIDON_STATE_SIZE: usize = 12;
pub const POSEIDON_HALF_FULL_ROUNDS: usize = 4;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 22;
pub const POSEIDON_TOTAL_ROUNDS: usize =
    2 * POSEIDON_HALF_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;

pub type Digest = [u64; 4];

#[inline]
fn gl_add(a: u64, b: u64) -> u64 {
    let a_u128 = a as u128 % GOLDILOCKS_PRIME as u128;
    let b_u128 = b as u128 % GOLDILOCKS_PRIME as u128;
    ((a_u128 + b_u128) % GOLDILOCKS_PRIME as u128) as u64
}

#[inline]
fn gl_sub(a: u64, b: u64) -> u64 {
    let a_u128 = a as u128 % GOLDILOCKS_PRIME as u128;
    let b_u128 = b as u128 % GOLDILOCKS_PRIME as u128;
    ((a_u128 + GOLDILOCKS_PRIME as u128 - b_u128) % GOLDILOCKS_PRIME as u128) as u64
}

#[inline]
fn gl_mul(a: u64, b: u64) -> u64 {
    let a_u128 = a as u128 % GOLDILOCKS_PRIME as u128;
    let b_u128 = b as u128 % GOLDILOCKS_PRIME as u128;
    ((a_u128 * b_u128) % GOLDILOCKS_PRIME as u128) as u64
}

fn gl_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut res = 1u64;
    while exp > 0 {
        if exp & 1 == 1 {
            res = gl_mul(res, base);
        }
        base = gl_mul(base, base);
        exp >>= 1;
    }
    res
}

#[inline]
fn gl_inv(a: u64) -> u64 {
    assert!(a != 0, "attempted inversion of zero");
    gl_pow(a, GOLDILOCKS_PRIME - 2)
}

#[inline]
fn is_power_of_two(x: usize) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

#[inline]
fn flatten_digests(digests: &[Digest]) -> Vec<u64> {
    let mut out = Vec::with_capacity(digests.len() * 4);
    for d in digests {
        out.extend_from_slice(d);
    }
    out
}

#[inline]
fn unflatten_digests(words: &[u64]) -> Vec<Digest> {
    assert!(words.len() % 4 == 0);
    let mut out = Vec::with_capacity(words.len() / 4);
    for chunk in words.chunks_exact(4) {
        out.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    out
}

#[inline]
fn poseidon_pow_7(x: u64) -> u64 {
    let x2 = gl_mul(x, x);
    let x3 = gl_mul(x2, x);
    let x4 = gl_mul(x2, x2);
    gl_mul(x3, x4)
}

fn poseidon_add_round_constants(state: &mut [u64; POSEIDON_STATE_SIZE], round: usize) {
    for i in 0..POSEIDON_STATE_SIZE {
        state[i] = gl_add(state[i], POSEIDON_ROUND_CONSTANTS[round][i]);
    }
}

fn poseidon_sbox_full(state: &mut [u64; POSEIDON_STATE_SIZE]) {
    for i in 0..POSEIDON_STATE_SIZE {
        state[i] = poseidon_pow_7(state[i]);
    }
}

fn poseidon_sbox_partial(state: &mut [u64; POSEIDON_STATE_SIZE]) {
    state[0] = poseidon_pow_7(state[0]);
}

fn poseidon_mds_multiply(state: &mut [u64; POSEIDON_STATE_SIZE]) {
    let mut next_state = [0u64; POSEIDON_STATE_SIZE];
    for i in 0..POSEIDON_STATE_SIZE {
        let mut sum = 0u64;
        for j in 0..POSEIDON_STATE_SIZE {
            sum = gl_add(sum, gl_mul(POSEIDON_MDS_MATRIX[i][j], state[j]));
        }
        next_state[i] = sum;
    }
    state.copy_from_slice(&next_state);
}

fn poseidon_permute(state: &mut [u64; POSEIDON_STATE_SIZE]) {
    let mut round_ctr = 0usize;

    for _ in 0..POSEIDON_HALF_FULL_ROUNDS {
        poseidon_add_round_constants(state, round_ctr);
        poseidon_sbox_full(state);
        poseidon_mds_multiply(state);
        round_ctr += 1;
    }

    for _ in 0..POSEIDON_PARTIAL_ROUNDS {
        poseidon_add_round_constants(state, round_ctr);
        poseidon_sbox_partial(state);
        poseidon_mds_multiply(state);
        round_ctr += 1;
    }

    for _ in 0..POSEIDON_HALF_FULL_ROUNDS {
        poseidon_add_round_constants(state, round_ctr);
        poseidon_sbox_full(state);
        poseidon_mds_multiply(state);
        round_ctr += 1;
    }
}

pub(crate) fn poseidon_hash_pair(left: &Digest, right: &Digest) -> Digest {
    let mut state = [0u64; POSEIDON_STATE_SIZE];
    state[4..8].copy_from_slice(left);
    state[8..12].copy_from_slice(right);
    poseidon_permute(&mut state);
    [state[0], state[1], state[2], state[3]]
}

fn build_merkle_tree_cpu(leaves: &[Digest]) -> Vec<Digest> {
    assert!(!leaves.is_empty());
    assert!(is_power_of_two(leaves.len()));

    let total_nodes = 2 * leaves.len() - 1;
    let mut tree = vec![[0u64; 4]; total_nodes];

    for (i, leaf) in leaves.iter().enumerate() {
        tree[i] = *leaf;
    }

    let mut current_layer_start = 0usize;
    let mut current_layer_size = leaves.len();
    let mut next_write_start = current_layer_size;

    while current_layer_size > 1 {
        let next_layer_size = current_layer_size / 2;
        for i in 0..next_layer_size {
            let left = tree[current_layer_start + 2 * i];
            let right = tree[current_layer_start + 2 * i + 1];
            tree[next_write_start + i] = poseidon_hash_pair(&left, &right);
        }
        current_layer_start = next_write_start;
        next_write_start += next_layer_size;
        current_layer_size = next_layer_size;
    }

    tree
}

fn merkle_root_from_tree(tree: &[Digest]) -> Digest {
    *tree.last().expect("tree must not be empty")
}

fn extract_merkle_proof(tree: &[Digest], leaf_idx: usize, domain_size: usize) -> Vec<Digest> {
    assert!(domain_size > 0);
    assert!(leaf_idx < domain_size);
    assert_eq!(tree.len(), 2 * domain_size - 1);

    let mut proof = Vec::new();
    let mut current_layer_size = domain_size;
    let mut layer_start_offset = 0usize;
    let mut current_rel_idx = leaf_idx;

    while current_layer_size > 1 {
        let sibling_rel_idx = current_rel_idx ^ 1;
        let sibling_abs_idx = layer_start_offset + sibling_rel_idx;
        proof.push(tree[sibling_abs_idx]);

        layer_start_offset += current_layer_size;
        current_layer_size /= 2;
        current_rel_idx /= 2;
    }

    proof
}

fn verify_merkle_path(leaf_idx: usize, leaf: &Digest, proof: &[Digest], root: &Digest) -> bool {
    let mut current_hash = *leaf;
    let mut current_idx = leaf_idx;

    for sibling in proof {
        current_hash = if current_idx % 2 == 0 {
            poseidon_hash_pair(&current_hash, sibling)
        } else {
            poseidon_hash_pair(sibling, &current_hash)
        };
        current_idx /= 2;
    }

    current_hash == *root
}

#[derive(Clone, Debug)]
struct Transcript {
    state: Digest,
    counter: u64,
}

impl Transcript {
    fn new() -> Self {
        let mut t = Self {
            state: [0u64; 4],
            counter: 0,
        };
        t.absorb_digest(&[0x51494E47, 0x465249, 1, 0]);
        t
    }

    fn absorb_u64(&mut self, value: u64) {
        self.absorb_digest(&[value, 0, 0, 0]);
    }

    fn absorb_digest(&mut self, d: &Digest) {
        self.state = poseidon_hash_pair(&self.state, d);
    }

    fn squeeze_digest(&mut self) -> Digest {
        let out = poseidon_hash_pair(&self.state, &[self.counter, 0, 0, 0]);
        self.state = out;
        self.counter = self.counter.wrapping_add(1);
        out
    }

    fn squeeze_field(&mut self) -> u64 {
        let x = self.squeeze_digest()[0] % GOLDILOCKS_PRIME;
        if x == 0 { 1 } else { x }
    }

    fn squeeze_usize(&mut self, bound: usize) -> usize {
        assert!(bound > 0);
        (self.squeeze_digest()[0] as usize) % bound
    }
}

#[derive(Clone, Debug)]
pub struct FriConfig {
    pub num_queries: usize,
    pub final_codeword_size: usize,
    pub domain_generator: u64,
    pub domain_offset: u64,
}

impl FriConfig {
    pub fn validate(&self, initial_domain_size: usize) {
        assert!(self.num_queries > 0, "num_queries must be > 0");
        assert!(is_power_of_two(initial_domain_size), "initial_domain_size must be power of two");
        assert!(
            is_power_of_two(self.final_codeword_size),
            "final_codeword_size must be power of two"
        );
        assert!(
            self.final_codeword_size > 0 && self.final_codeword_size <= initial_domain_size,
            "invalid final_codeword_size"
        );
        assert!(
            initial_domain_size % self.final_codeword_size == 0,
            "initial_domain_size must be divisible by final_codeword_size"
        );
    }
}

#[derive(Clone, Debug)]
pub struct FriLayerOpening {
    pub layer_index: usize,
    pub domain_size: usize,
    pub local_index: usize,
    pub x_index: usize,
    pub x_eval: Digest,
    pub x_proof: Vec<Digest>,
    pub neg_x_index: usize,
    pub neg_x_eval: Digest,
    pub neg_x_proof: Vec<Digest>,
}

#[derive(Clone, Debug)]
pub struct FriQuery {
    pub initial_index: usize,
    pub layers: Vec<FriLayerOpening>,
}

#[derive(Clone, Debug)]
pub struct FriProof {
    pub config: FriConfig,
    pub roots: Vec<Digest>,
    pub final_codeword: Vec<Digest>,
    pub queries: Vec<FriQuery>,
}

#[derive(Clone, Debug)]
struct ProverLayer {
    domain_size: usize,
    codeword: Vec<Digest>,
    tree: Vec<Digest>,
    root: Digest,
}

#[derive(Clone, Debug)]
struct ProverState {
    layers: Vec<ProverLayer>,
    final_codeword: Vec<Digest>,
}

#[inline(always)]
fn fold_pair(f_x: &Digest, f_neg_x: &Digest, alpha: u64, half_inv: u64, x_inv: u64) -> Digest {
    let mut out = [0u64; 4];
    let two_x_inv = gl_mul(half_inv, x_inv);

    for j in 0..4 {
        let sum = gl_add(f_x[j], f_neg_x[j]);
        let term1 = gl_mul(sum, half_inv);

        let diff = gl_sub(f_x[j], f_neg_x[j]);
        let diff_over_2x = gl_mul(diff, two_x_inv);
        let term2 = gl_mul(alpha, diff_over_2x);

        out[j] = gl_add(term1, term2);
    }
    out
}


pub struct FriProver<'a> {
    engine: &'a QingmingEngine,
    config: FriConfig,
}

impl<'a> FriProver<'a> {
    pub fn new(engine: &'a QingmingEngine, config: FriConfig) -> Self {
        Self { engine, config }
    }

    pub fn prove(&self, stream_id: i32, initial_codeword_flat: &[u64]) -> FriProof {
        assert!(
            initial_codeword_flat.len() % 4 == 0,
            "initial_codeword_flat length must be multiple of 4"
        );

        let initial_domain_size = initial_codeword_flat.len() / 4;
        self.config.validate(initial_domain_size);

        let state = self.commit_and_fold(stream_id, initial_codeword_flat);
        let roots: Vec<Digest> = state.layers.iter().map(|l| l.root).collect();

        let mut transcript = self.build_transcript_header(initial_domain_size);
        for (i, root) in roots.iter().enumerate() {
            transcript.absorb_digest(root);
            if i + 1 < roots.len() {
                let _ = transcript.squeeze_field();
            }
        }

        let query_bound = initial_domain_size / 2;
        let query_indices = self.sample_query_indices(&mut transcript, query_bound);
        let queries = self.open_queries(&state, &query_indices);

        FriProof {
            config: self.config.clone(),
            roots,
            final_codeword: state.final_codeword,
            queries,
        }
    }

    fn commit_and_fold(&self, stream_id: i32, initial_codeword_flat: &[u64]) -> ProverState {
        let mut current_domain_size = initial_codeword_flat.len() / 4;
        let mut current_codeword: Vec<Digest> = unsafe {
            std::slice::from_raw_parts(
                initial_codeword_flat.as_ptr() as *const Digest,
                current_domain_size,
            )
        }.to_vec(); 

        let mut layers = Vec::new();
        let mut transcript = self.build_transcript_header(current_domain_size);

        loop {
            let total_nodes = 2 * current_domain_size - 1;
            let mut tree_flat = vec![0u64; total_nodes * 4];

            let codeword_flat_ptr = unsafe {
                std::slice::from_raw_parts(
                    current_codeword.as_ptr() as *const u64,
                    current_codeword.len() * 4,
                )
            };

            self.engine.build_merkle_tree_async(
                stream_id,
                codeword_flat_ptr,
                &mut tree_flat,
                current_domain_size as i32,
            );
            self.engine.wait_stream(stream_id);

            let tree: Vec<Digest> = unsafe {
                let ptr = tree_flat.as_mut_ptr() as *mut Digest;
                let len = tree_flat.len() / 4;
                let cap = tree_flat.capacity() / 4;
                std::mem::forget(tree_flat); 
                Vec::from_raw_parts(ptr, len, cap)
            };

            let root = merkle_root_from_tree(&tree);

            layers.push(ProverLayer {
                domain_size: current_domain_size,
                codeword: current_codeword.clone(),
                tree,
                root,
            });

            transcript.absorb_digest(&root);
            if current_domain_size == self.config.final_codeword_size {
                break;
            }

            let alpha = transcript.squeeze_field();
            let next_domain_size = current_domain_size / 2;
            let mut next_codeword = vec![[0u64; 4]; next_domain_size];
            let layer_index = layers.len() - 1;
            let omega_k = gl_pow(self.config.domain_generator, 1u64 << layer_index);
            let offset_k = gl_pow(self.config.domain_offset, 1u64 << layer_index);
            let omega_k_inv = gl_inv(omega_k);
            let mut current_x_inv = gl_inv(offset_k);
            let half_inv = 0x7FFFFFFF80000001u64;
            for i in 0..next_domain_size {
                let f_x = current_codeword[i];
                let f_neg_x = current_codeword[i + next_domain_size];                
                next_codeword[i] = fold_pair(&f_x, &f_neg_x, alpha, half_inv, current_x_inv);
                current_x_inv = gl_mul(current_x_inv, omega_k_inv); 
            }

            current_codeword = next_codeword;
            current_domain_size = next_domain_size;
        }

        ProverState {
            final_codeword: current_codeword,
            layers,
        }
    }



    fn open_queries(&self, state: &ProverState, query_indices: &[usize]) -> Vec<FriQuery> {
        let mut out = Vec::with_capacity(query_indices.len());

        for &initial_index in query_indices {
            let mut current_idx = initial_index;
            let mut layers_opened = Vec::new();

            for (layer_idx, layer) in state.layers.iter().enumerate() {
                if layer.domain_size == self.config.final_codeword_size {
                    break;
                }

                let half = layer.domain_size / 2;
                let local_index = current_idx % half;

                let x_index = local_index;
                let neg_x_index = local_index + half;

                let x_eval = layer.codeword[x_index];
                let neg_x_eval = layer.codeword[neg_x_index];

                let x_proof = extract_merkle_proof(&layer.tree, x_index, layer.domain_size);
                let neg_x_proof = extract_merkle_proof(&layer.tree, neg_x_index, layer.domain_size);

                layers_opened.push(FriLayerOpening {
                    layer_index: layer_idx,
                    domain_size: layer.domain_size,
                    local_index,
                    x_index,
                    x_eval,
                    x_proof,
                    neg_x_index,
                    neg_x_eval,
                    neg_x_proof,
                });

                current_idx = local_index;
            }

            out.push(FriQuery {
                initial_index,
                layers: layers_opened,
            });
        }

        out
    }

    fn build_transcript_header(&self, initial_domain_size: usize) -> Transcript {
        let mut t = Transcript::new();
        t.absorb_u64(initial_domain_size as u64);
        t.absorb_u64(self.config.final_codeword_size as u64);
        t.absorb_u64(self.config.num_queries as u64);
        t.absorb_u64(self.config.domain_generator);
        t.absorb_u64(self.config.domain_offset);
        t
    }

    fn sample_query_indices(&self, transcript: &mut Transcript, bound: usize) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.config.num_queries);
        for _ in 0..self.config.num_queries {
            out.push(transcript.squeeze_usize(bound));
        }
        out
    }

    fn domain_point(&self, layer_index: usize, local_index: usize) -> u64 {
        let omega_k = gl_pow(self.config.domain_generator, 1u64 << layer_index);
        let offset_k = gl_pow(self.config.domain_offset, 1u64 << layer_index);
        gl_mul(offset_k, gl_pow(omega_k, local_index as u64))
    }
}

pub struct FriVerifier {
    config: FriConfig,
}

impl FriVerifier {
    pub fn new(config: FriConfig) -> Self {
        Self { config }
    }

    pub fn verify(&self, proof: &FriProof) -> bool {
        if proof.roots.is_empty() {
            println!("verify failed: proof.roots is empty");
            return false;
        }

        if proof.config.num_queries != self.config.num_queries
            || proof.config.final_codeword_size != self.config.final_codeword_size
            || proof.config.domain_generator != self.config.domain_generator
            || proof.config.domain_offset != self.config.domain_offset
        {
            println!("verify failed: config mismatch");
            println!("proof.config = {:?}", proof.config);
            println!("self.config  = {:?}", self.config);
            return false;
        }

        let initial_domain_size = match self.derive_initial_domain_size(proof) {
            Some(v) => v,
            None => {
                println!("verify failed: could not derive initial_domain_size");
                return false;
            }
        };

        self.config.validate(initial_domain_size);

        if proof.final_codeword.len() != self.config.final_codeword_size {
            println!(
                "verify failed: final_codeword size mismatch, got {}, expected {}",
                proof.final_codeword.len(),
                self.config.final_codeword_size
            );
            return false;
        }

        let final_tree = build_merkle_tree_cpu(&proof.final_codeword);
        let final_root = merkle_root_from_tree(&final_tree);
        let claimed_final_root = *proof.roots.last().unwrap();

        if final_root != claimed_final_root {
            println!("verify failed: final root mismatch");
            println!("cpu final root     = {:?}", final_root);
            println!("claimed final root = {:?}", claimed_final_root);
            return false;
        }

        let mut transcript = self.build_transcript_header(initial_domain_size);
        let mut alphas = Vec::with_capacity(proof.roots.len().saturating_sub(1));

        for (i, root) in proof.roots.iter().enumerate() {
            transcript.absorb_digest(root);
            if i + 1 < proof.roots.len() {
                alphas.push(transcript.squeeze_field());
            }
        }

        let expected_query_indices =
            self.sample_query_indices(&mut transcript, initial_domain_size / 2);

        if expected_query_indices.len() != proof.queries.len() {
            println!(
                "verify failed: query count mismatch, expected {}, got {}",
                expected_query_indices.len(),
                proof.queries.len()
            );
            return false;
        }

        for (query_idx, (query, expected_initial_index)) in
            proof.queries.iter().zip(expected_query_indices.iter()).enumerate()
        {
            if query.initial_index != *expected_initial_index {
                println!(
                    "verify failed: query initial index mismatch at query {}: got {}, expected {}",
                    query_idx,
                    query.initial_index,
                    expected_initial_index
                );
                return false;
            }

            if !self.verify_query(query, proof, &alphas) {
                println!("verify failed: verify_query failed at query {}", query_idx);
                return false;
            }
        }

        true
    }

    fn verify_query(&self, query: &FriQuery, proof: &FriProof, alphas: &[u64]) -> bool {
        if query.layers.len() != alphas.len() {
            return false;
        }

        let mut current_idx = query.initial_index;
        let mut expected_next_value = None;

        for (layer_idx, opening) in query.layers.iter().enumerate() {
            if opening.layer_index != layer_idx {
                return false;
            }

            let expected_domain_size = self.derive_layer_domain_size(proof, layer_idx);
            if opening.domain_size != expected_domain_size {
                return false;
            }

            let half = opening.domain_size / 2;
            if half == 0 {
                return false;
            }

            let local_index = current_idx % half;

            if opening.local_index != local_index {
                return false;
            }
            if opening.x_index != local_index {
                return false;
            }
            if opening.neg_x_index != local_index + half {
                return false;
            }

            let root = &proof.roots[layer_idx];

            if !verify_merkle_path(opening.x_index, &opening.x_eval, &opening.x_proof, root) {
                return false;
            }
            if !verify_merkle_path(
                opening.neg_x_index,
                &opening.neg_x_eval,
                &opening.neg_x_proof,
                root,
            ) {
                return false;
            }
            let x = self.domain_point(layer_idx, local_index);
            let x_inv = gl_inv(x); 
            let half_inv = 0x7FFFFFFF80000001u64;           
            let folded = fold_pair(&opening.x_eval, &opening.neg_x_eval, alphas[layer_idx], half_inv, x_inv);
            expected_next_value = Some(folded);
            current_idx = local_index;
        }

        match expected_next_value {
            Some(v) => proof.final_codeword[current_idx] == v,
            None => {
                if proof.final_codeword.len() != 1 {
                    return false;
                }
                proof.final_codeword[0] == proof.final_codeword[current_idx]
            }
        }
    }

    fn derive_initial_domain_size(&self, proof: &FriProof) -> Option<usize> {
        let folds = proof.roots.len().checked_sub(1)?;
        let mut size = proof.final_codeword.len();
        for _ in 0..folds {
            size = size.checked_mul(2)?;
        }
        Some(size)
    }

    fn derive_layer_domain_size(&self, proof: &FriProof, layer_idx: usize) -> usize {
        self.derive_initial_domain_size(proof).unwrap() >> layer_idx
    }

    fn build_transcript_header(&self, initial_domain_size: usize) -> Transcript {
        let mut t = Transcript::new();
        t.absorb_u64(initial_domain_size as u64);
        t.absorb_u64(self.config.final_codeword_size as u64);
        t.absorb_u64(self.config.num_queries as u64);
        t.absorb_u64(self.config.domain_generator);
        t.absorb_u64(self.config.domain_offset);
        t
    }

    fn sample_query_indices(&self, transcript: &mut Transcript, bound: usize) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.config.num_queries);
        for _ in 0..self.config.num_queries {
            out.push(transcript.squeeze_usize(bound));
        }
        out
    }

    fn domain_point(&self, layer_index: usize, local_index: usize) -> u64 {
        let omega_k = gl_pow(self.config.domain_generator, 1u64 << layer_index);
        let offset_k = gl_pow(self.config.domain_offset, 1u64 << layer_index);
        gl_mul(offset_k, gl_pow(omega_k, local_index as u64))
    }
}

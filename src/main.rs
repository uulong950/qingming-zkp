use qingming_zkp_rs::fri::{FriConfig, FriProver, FriVerifier};
use qingming_zkp_rs::poseidon_constants::{
    POSEIDON_MDS_MATRIX, POSEIDON_MDS_MATRIX_FLAT, POSEIDON_ROUND_CONSTANTS,
    POSEIDON_ROUND_CONSTANTS_FLAT,
};
use qingming_zkp_rs::QingmingEngine;
use std::env;
use std::time::Instant;

const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;
const POSEIDON_STATE_SIZE: usize = 12;
const POSEIDON_HALF_FULL_ROUNDS: usize = 4;
const POSEIDON_PARTIAL_ROUNDS: usize = 22;

type Digest = [u64; 4];

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

fn poseidon_hash_pair(left: &Digest, right: &Digest) -> Digest {
    let mut state = [0u64; POSEIDON_STATE_SIZE];
    state[4..8].copy_from_slice(left);
    state[8..12].copy_from_slice(right);
    poseidon_permute(&mut state);
    [state[0], state[1], state[2], state[3]]
}

fn build_merkle_root_cpu(leaves: &[Digest]) -> Digest {
    assert!(!leaves.is_empty());
    assert!(leaves.len().is_power_of_two());
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);
        for i in 0..(current.len() / 2) {
            next.push(poseidon_hash_pair(&current[2 * i], &current[2 * i + 1]));
        }
        current = next;
    }
    current[0]
}

fn bit_reverse(mut x: usize, log_n: usize) -> usize {
    let mut y = 0usize;
    for _ in 0..log_n {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    y
}

fn cpu_ntt_radix2_dit(values: &[u64], omega: u64) -> Vec<u64> {
    let n = values.len();
    assert!(n.is_power_of_two());
    let log_n = n.trailing_zeros() as usize;
    let mut a = values.to_vec();
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2usize;
    while len <= n {
        let w_len = gl_pow(omega, (n / len) as u64);
        for start in (0..n).step_by(len) {
            let mut w = 1u64;
            for j in 0..(len / 2) {
                let u = a[start + j];
                let v = gl_mul(a[start + j + len / 2], w);
                a[start + j] = gl_add(u, v);
                a[start + j + len / 2] = gl_sub(u, v);
                w = gl_mul(w, w_len);
            }
        }
        len <<= 1;
    }
    a
}

fn gpu_root_from_tree_buffer(tree_buffer: &[u64]) -> Digest {
    let n = tree_buffer.len();
    assert!(n >= 4);
    [tree_buffer[n - 4], tree_buffer[n - 3], tree_buffer[n - 2], tree_buffer[n - 1]]
}

fn speedup(cpu_secs: f64, gpu_secs: f64) -> f64 {
    if gpu_secs == 0.0 {
        f64::INFINITY
    } else {
        cpu_secs / gpu_secs
    }
}

fn words_to_digests(words: &[u64]) -> Vec<Digest> {
    assert!(words.len() % 4 == 0);
    words.chunks_exact(4)
        .map(|c| [c[0], c[1], c[2], c[3]])
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = if args.len() > 1 { args[1].to_lowercase() } else { "all".to_string() };

    if mode != "cpu" && mode != "gpu" && mode != "all" {
        eprintln!("Usage: cargo run --release -- [cpu|gpu|all]");
        std::process::exit(1);
    }

    println!("\n============================================================");
    println!(" 🚀 QINGMING ZKP ENGINE: GPU VS CPU L0 BENCH 🚀");
    println!("============================================================");
    println!("  [TARGET DEVICE]  AMD Radeon RX 7900 XTX (24GB VRAM)");
    println!("  [MEMORY LAYER]   96MB L3 Infinity Cache (Saturated)");
    println!("  [EXECUTION MODE] [{}]", mode.to_uppercase());
    println!("------------------------------------------------------------");
    println!("  \x1b[1;31m[!] CRITICAL: Binary `libqingming.so` is HARDWARE-LOCKED.\x1b[0m");
    println!("  \x1b[1;31m[!] STRICT REQUIREMENT: ldd (Ubuntu GLIBC 2.39-0ubuntu8.7) 2.39.\x1b[0m");
    println!("  \x1b[1;31m[!] Execution on unauthorized hardware triggers HIP Context Crash.\x1b[0m");
    println!("============================================================\n");

    let power = 24usize;
    let n_size = 1usize << power;
    let u64_per_element = 4usize;
    let buffer_len = n_size * u64_per_element;

    let cpu_ntt_power = 24usize;
    let cpu_ntt_size = 1usize << cpu_ntt_power;

    let fri_config = FriConfig {
        num_queries: 3,
        final_codeword_size: 128,
        domain_generator: 7,
        domain_offset: 1,
    };

    println!("[+] GPU platform target: 2^{} elements", power);
    println!("[+] CPU NTT baseline size: 2^{}", cpu_ntt_power);
    println!("[+] CPU Merkle baseline size: 2^{}\n", power);

    let total_start = Instant::now();

    let mut gpu_ntt_secs = 0.0;
    let mut gpu_merkle_secs = 0.0;
    let mut gpu_verify_secs = 0.0;
    let mut cpu_ntt_secs = 0.0;
    let mut cpu_merkle_secs = 0.0;
    let mut cpu_verify_secs = 0.0;

    let mut proof_opt = None;
    let mut gpu_merkle_root_opt = None;
    let mut ntt_result_gpu_opt = None;

    if mode == "gpu" || mode == "all" {
        let engine = QingmingEngine::new(1);
        engine.load_poseidon_constants(&POSEIDON_ROUND_CONSTANTS_FLAT, &POSEIDON_MDS_MATRIX_FLAT);

        let input_poly_gpu = vec![1u64; buffer_len];
        let mut ntt_result_gpu = vec![0u64; buffer_len];
        let total_merkle_nodes = n_size * 2 - 1;
        let mut merkle_tree_buffer_gpu = vec![0u64; total_merkle_nodes * u64_per_element];

        engine.ntt_async(0, &input_poly_gpu, &mut ntt_result_gpu);
        engine.build_merkle_tree_async(0, &ntt_result_gpu, &mut merkle_tree_buffer_gpu, n_size as i32);
        engine.wait_stream(0);

        let prover = FriProver::new(&engine, fri_config.clone());
        let warmup_proof = prover.prove(0, &ntt_result_gpu);
        let verifier = FriVerifier::new(fri_config.clone());
        assert!(verifier.verify(&warmup_proof));

        let t_gpu_ntt = Instant::now();
        engine.ntt_async(0, &input_poly_gpu, &mut ntt_result_gpu);
        engine.wait_stream(0);
        let gpu_ntt_duration = t_gpu_ntt.elapsed();
        gpu_ntt_secs = gpu_ntt_duration.as_secs_f64();

        let t_gpu_merkle = Instant::now();
        engine.build_merkle_tree_async(0, &ntt_result_gpu, &mut merkle_tree_buffer_gpu, n_size as i32);
        engine.wait_stream(0);
        let gpu_merkle_duration = t_gpu_merkle.elapsed();
        gpu_merkle_secs = gpu_merkle_duration.as_secs_f64();
        let gpu_merkle_root = gpu_root_from_tree_buffer(&merkle_tree_buffer_gpu);

        let t_gpu_prove = Instant::now();
        let proof = prover.prove(0, &ntt_result_gpu);
        let gpu_prove_duration = t_gpu_prove.elapsed();

        let t_gpu_verify = Instant::now();
        let is_valid_gpu = verifier.verify(&proof);
        let gpu_verify_duration = t_gpu_verify.elapsed();
        gpu_verify_secs = gpu_verify_duration.as_secs_f64();
        assert!(is_valid_gpu);

        println!("========================= GPU RESULTS =========================");
        println!("  GPU NTT Size:                    2^{} ({})", power, n_size);
        println!("  GPU NTT Latency:                 \x1b[1;33m{:.4?}\x1b[0m", gpu_ntt_duration);
        println!("  GPU L0 Merkle Size:              2^{} ({})", power, n_size);
        println!("  GPU L0 Merkle Latency:           \x1b[1;35m{:.4?}\x1b[0m", gpu_merkle_duration);
        println!("  GPU FRI Prove Latency:           \x1b[1;36m{:.4?}\x1b[0m", gpu_prove_duration);
        println!("  GPU FRI Verify Latency:          \x1b[1;34m{:.4?}\x1b[0m", gpu_verify_duration);
        println!("  GPU L0 Root:                     {:?}", gpu_merkle_root);
        println!("===============================================================\n");

        proof_opt = Some(proof);
        gpu_merkle_root_opt = Some(gpu_merkle_root);
        ntt_result_gpu_opt = Some(ntt_result_gpu);
    }

    if mode == "cpu" || mode == "all" {
        let cpu_ntt_input = vec![1u64; cpu_ntt_size];
        let omega = gl_pow(7, (GOLDILOCKS_PRIME - 1) / cpu_ntt_size as u64);

        let t_cpu_ntt = Instant::now();
        let cpu_ntt_output = cpu_ntt_radix2_dit(&cpu_ntt_input, omega);
        let cpu_ntt_duration = t_cpu_ntt.elapsed();
        cpu_ntt_secs = cpu_ntt_duration.as_secs_f64();
        assert_eq!(cpu_ntt_output.len(), cpu_ntt_size);

        let t_cpu_merkle = Instant::now();
        let cpu_merkle_root = if let Some(ref ntt_gpu) = ntt_result_gpu_opt {
            let cpu_merkle_leaves = words_to_digests(ntt_gpu);
            build_merkle_root_cpu(&cpu_merkle_leaves)
        } else {
            let mut dummy_leaves = vec![[0u64; 4]; n_size];
            for i in 0..std::cmp::min(n_size, cpu_ntt_size) {
                dummy_leaves[i][0] = cpu_ntt_output[i];
            }
            build_merkle_root_cpu(&dummy_leaves)
        };
        let cpu_merkle_duration = t_cpu_merkle.elapsed();
        cpu_merkle_secs = cpu_merkle_duration.as_secs_f64();

        if let Some(gpu_root) = gpu_merkle_root_opt {
            assert_eq!(cpu_merkle_root, gpu_root);
        }

        println!("========================= CPU RESULTS =========================");
        println!("  CPU NTT Size:                    2^{} ({})", cpu_ntt_power, cpu_ntt_size);
        println!("  CPU NTT Latency:                 \x1b[1;33m{:.4?}\x1b[0m", cpu_ntt_duration);
        println!("  CPU Merkle Size:                 2^{} ({})", power, n_size);
        println!("  CPU Merkle Latency:              \x1b[1;35m{:.4?}\x1b[0m", cpu_merkle_duration);

        if let Some(ref proof) = proof_opt {
            let t_cpu_verify = Instant::now();
            let verifier_cpu = FriVerifier::new(fri_config.clone());
            let is_valid_cpu = verifier_cpu.verify(proof);
            let cpu_verify_duration = t_cpu_verify.elapsed();
            cpu_verify_secs = cpu_verify_duration.as_secs_f64();
            assert!(is_valid_cpu);
            println!("  CPU FRI Verify Latency:          \x1b[1;34m{:.4?}\x1b[0m", cpu_verify_duration);
        } else {
            println!("  CPU FRI Verify Latency:          \x1b[1;31mN/A (Requires GPU Proof)\x1b[0m");
        }
        println!("  CPU Merkle Root:                 {:?}", cpu_merkle_root);
        println!("===============================================================\n");
    }

    if mode == "all" {
        println!("===================== GPU VS CPU SPEEDUP =====================");
        println!("  NTT Speedup (CPU/GPU):           \x1b[1;32m{:.2}x\x1b[0m", speedup(cpu_ntt_secs, gpu_ntt_secs));
        println!("  Merkle Speedup (CPU/GPU):        \x1b[1;32m{:.2}x\x1b[0m", speedup(cpu_merkle_secs, gpu_merkle_secs));
        if gpu_verify_secs > 0.0 && cpu_verify_secs > 0.0 {
            println!("  Verify Speedup (CPU/GPU):        \x1b[1;32m{:.2}x\x1b[0m", speedup(cpu_verify_secs, gpu_verify_secs));
        }
        println!("===============================================================\n");
    }

    if let Some(proof) = proof_opt {
        let total_duration = total_start.elapsed();
        println!("====================== PROOF PIPELINE META ====================");
        println!("  Queries:                         {}", fri_config.num_queries);
        println!("   Codeword Size:             {}", fri_config.final_codeword_size);
        println!("  Proof Roots:                     {}", proof.roots.len());
        println!("  Proof Queries:                   {}", proof.queries.len());
        println!("   Codeword Length:           {}", proof.final_codeword.len());
        println!("  Total Mixed Benchmark Time:      \x1b[1;32m{:.4?}\x1b[0m", total_duration);
        println!("===============================================================\n");
    }
}

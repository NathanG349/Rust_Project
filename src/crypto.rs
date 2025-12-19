// Ce fichier contient toute la cryptographie du projet
use rand::Rng;

//  CONSTANTES
pub const P: u64 = 0xD87FA3E291B4C7F3; // Nombre premier
pub const G: u64 = 2; // Générateur

// Paramètres LCG
const LCG_A: u64 = 1103515245;
const LCG_C: u64 = 12345;
const LCG_M: u64 = 4294967296;

/// Exponentiation Modulaire : (base^exp) % modulus
pub fn pow_mod(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result as u128 * base as u128 % modulus as u128) as u64;
        }
        base = (base as u128 * base as u128 % modulus as u128) as u64;
        exp /= 2;
    }
    result
}

/// Générateur de nombres pseudo-aléatoires (LCG) pour le keystream
pub struct Lcg {
    state: u64,
}

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Génère le prochain octet du keystream
    pub fn next_byte(&mut self) -> u8 {
        self.state = (LCG_A.wrapping_mul(self.state).wrapping_add(LCG_C)) % LCG_M;
        (self.state >> 24) as u8
    }
}

/// Fonction utilitaire pour générer une clé privée
pub fn generate_private_key() -> u64 {
    let mut rng = rand::rng();
    rng.random()
}

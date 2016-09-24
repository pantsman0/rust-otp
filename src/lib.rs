extern crate hmacsha1;
extern crate time;

use hmacsha1::{SHA1_DIGEST_BYTES, hmac_sha1};
use time::{Timespec,Duration};

pub fn hotp( secret: &[u8], counter: u64) -> u32 {
  // build hmac key from counter
  let hmac_message: &[u8; 8] = &[
    ( ( counter >> 56 ) & 0xff ) as u8,
    ( ( counter >> 48 ) & 0xff ) as u8,
    ( ( counter >> 40 ) & 0xff ) as u8,
    ( ( counter >> 32 ) & 0xff ) as u8,
    ( ( counter >> 24 ) & 0xff ) as u8,
    ( ( counter >> 16 ) & 0xff ) as u8,
    ( ( counter >> 8 ) & 0xff ) as u8,
    ( ( counter >> 0 ) & 0xff ) as u8,
    ];

    // hmac the key and secret
    let hash = hmac_sha1(secret, hmac_message);

    // calculate the dynamic offset for the value
    let dynamic_offset = ( hash[SHA1_DIGEST_BYTES-1] & (0xf as u8) ) as usize ;

    // build the u32 code from the hash
    ( ( ( hash[dynamic_offset] as u32 ) & 0x7f ) << 24
    | ( hash[dynamic_offset+1] as u32 ) << 16
    | ( hash[dynamic_offset+2] as u32 ) << 8
    | ( hash[dynamic_offset+3] as u32 )
    ) as u32
}

pub fn hotp_validate(secret: &[u8], counter: u64, guess: u32, guess_digits: u32) -> bool {
    guess == ( hotp(secret, counter) % 10u32.pow(guess_digits) )
}

pub fn totp( secret: &[u8], time: Timespec, window: Duration) -> u32 {
    let counter: u64 = ( time.sec.abs() / window.num_seconds().abs() ) as u64;

    hotp(secret, counter)
}

pub fn totp_validate( secret: &[u8], time: Timespec, window_seconds: Duration, guess: u32,
                       guess_digits: u32) -> bool {
    guess == ( totp(secret, time, window_seconds) % 10u32.pow(guess_digits) )
}


#[cfg(test)]
mod tests {
    use time::{Timespec,Duration};

    use hotp;
    use hotp_validate;
    use totp;
    use totp_validate;

    // "12345678901234567890"
    const HOTP_TEST_SECRET: &'static[u8] = &[
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
    ];

    const HOTP_TEST_VALUES: [u32; 10] = [
        1284755224,
        1094287082,
        137359152,
        1726969429,
        1640338314,
        868254676,
        1918287922,
        82162583,
        673399871,
        645520489,
    ];

    #[test]
    fn test_hotp() {
        for counter in 0..10_usize {
            if HOTP_TEST_VALUES[counter] !=  hotp(HOTP_TEST_SECRET, counter as u64 ) {
                panic!("Expected {} for counter {}, found {}.", HOTP_TEST_VALUES[counter], counter,
                    hotp(HOTP_TEST_SECRET, counter as u64) );
            }
        }
    }

    #[test]
    fn test_hotp_4_digits() {
        for counter in 0..10_usize {
            if !hotp_validate(HOTP_TEST_SECRET, counter as u64 , HOTP_TEST_VALUES[counter] % 10u32.pow(4), 4) {
                panic!("Error validating code {} for counter {}.", HOTP_TEST_VALUES[counter] % 10u32.pow(4), counter);
            }
        }
    }

    #[test]
    fn test_totp() {
       for counter in 0..10_usize {
           let time: Timespec = Timespec { sec: counter as i64 * 30, nsec: 0};
           let window: Duration = Duration::seconds(30);
           if HOTP_TEST_VALUES[counter] !=  totp(HOTP_TEST_SECRET, time, window ) {
               panic!("Expected {} for counter {}, found {}.", HOTP_TEST_VALUES[counter], counter,
                    hotp(HOTP_TEST_SECRET, counter as u64) );
           }
       }
    }

    #[test]
    fn test_totp_4_digits() {
        for counter in 0..10_usize {
            let time: Timespec = Timespec { sec: counter as i64 * 30, nsec: 0};
            let window: Duration = Duration::seconds(30);
            if !totp_validate(HOTP_TEST_SECRET, time, window, HOTP_TEST_VALUES[counter] % 10u32.pow(4), 4) {
                panic!("Error validating code {} for counter {}.", HOTP_TEST_VALUES[counter] % 10u32.pow(4), counter);
            }
            if totp_validate(HOTP_TEST_SECRET, time+window, window, HOTP_TEST_VALUES[counter] % 10u32.pow(4), 4) {
                panic!("Error incorrectly validating code {} for counter {}.", HOTP_TEST_VALUES[counter] % 10u32.pow(4), counter+1);
            }
        }
    }
}
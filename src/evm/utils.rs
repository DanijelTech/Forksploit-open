use std::io::Write;

use colored::Colorize;
use regex::Regex;
use revm_primitives::U256;

use crate::input::ConciseSerde;

pub fn colored_address(addr: &str) -> String {
    let (r, g, b) = get_rgb_by_address(addr);
    addr.truecolor(r, g, b).to_string()
}

// The `[Sender]` and the address should be the same color.
pub fn colored_sender(sender: &str) -> String {
    let (r, g, b) = get_rgb_by_address(sender);
    format!("[Sender] {}", sender).truecolor(r, g, b).to_string()
}

pub fn prettify_value(value: U256) -> String {
    if value > U256::from(10).pow(U256::from(15)) {
        let one_eth = U256::from(10).pow(U256::from(18));
        let integer = value / one_eth;
        let remainder = value % one_eth;
        if remainder == U256::ZERO {
            return format!("{} ether", integer);
        }
        // Zero-pad the remainder to the full 18 decimal digits first (it is a
        // wei count below 1 ether, so a naive `to_string()` drops leading
        // zeros and silently misrepresents the magnitude -- e.g. a remainder
        // of 5 wei would render as "X.5 ether", i.e. half an ether too much,
        // instead of "X.000000000000000005 ether"). Trailing zeros are then
        // trimmed for readability; that's safe since they never change the
        // exact wei value. This keeps the result both human-readable AND an
        // exact, round-trippable Solidity numeric literal -- previously this
        // truncated to 4 decimal digits, which silently lost precision and
        // could emit a value that doesn't match the one that triggered the
        // bug when reused as a literal in generated exploit code.
        let mut decimal = format!("{:0>18}", remainder.to_string());
        while decimal.ends_with('0') {
            decimal.pop();
        }

        format!("{}.{} ether", integer, decimal)
    } else {
        value.to_string()
    }
}

/// Inverse of `prettify_value`: parses either a plain wei integer string
/// or a "<integer>[.<fraction>] ether" string back into a wei `u128`.
///
/// Needed because `Tx::value` (populated via `prettify_value`) is the only
/// representation kept once a trace has been converted into template-ready
/// `Tx`s, yet exploit script generation still needs the exact wei total to
/// fund the generated contract with. Plain `tx.value.parse::<u128>()`
/// silently returns `None` (and gets filtered out of the sum) for any
/// value above 0.001 ETH -- exactly when `prettify_value` starts
/// appending " ether", which isn't a valid integer literal. That means
/// the generated exploit script's `needs_funding` flag went to `false`
/// and the funding step (`vm.deal`/a plain `transfer`) was skipped
/// outright whenever an exploit's real required funding was more than a
/// trivial amount -- the exploit would then fail for real (insufficient
/// balance) despite looking correct in the fuzzer's own in-memory
/// simulation.
pub fn parse_pretty_wei(s: &str) -> Option<u128> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    match s.strip_suffix(" ether") {
        Some(num) => {
            let (int_part, frac_part) = num.split_once('.').unwrap_or((num, ""));
            let int_val: u128 = int_part.parse().ok()?;
            // prettify_value zero-pads the fraction to 18 digits before
            // trimming trailing zeros, so padding back on the right
            // reconstructs the exact original wei remainder.
            let frac_padded = format!("{:0<18}", frac_part);
            if frac_padded.len() != 18 {
                return None;
            }
            let frac_val: u128 = frac_padded.parse().ok()?;
            int_val.checked_mul(10u128.checked_pow(18)?)?.checked_add(frac_val)
        }
        None => s.parse().ok(),
    }
}

pub fn prettify_concise_inputs<CI: ConciseSerde>(inputs: &[CI]) -> String {
    let mut res = String::new();
    let mut sender = String::new();

    /*
     * The rules for replacing the last `├─` with `└─`:
     * 1. the indentation has reduced
     * 2. the sender has changed in the same layer
     * 3. the last input
     */
    let mut prev_indent_len = 0;
    let mut pending: Option<String> = None;

    for input in inputs {
        // Indentation has reduced.
        if input.indent().len() < prev_indent_len {
            push_last_input(&mut res, pending.take());
        }

        // Sender has changed
        if sender != input.sender() && !input.is_step() {
            // Print the pending input
            if let Some(s) = pending.take() {
                if input.indent().len() == prev_indent_len {
                    push_last_input(&mut res, Some(s)); // └─ call
                } else {
                    res.push_str(format!("{}\n", s).as_str()); // ├─ call
                }
            }

            // Print new sender
            sender = input.sender().clone();
            res.push_str(format!("{}{}\n", input.indent(), colored_sender(&sender)).as_str());
        }

        if let Some(s) = pending.take() {
            res.push_str(format!("{}\n", s).as_str());
        }
        pending = Some(input.serialize_string());
        prev_indent_len = input.indent().len();
    }

    push_last_input(&mut res, pending);
    res
}

pub fn remove_color(input: &str) -> String {
    let reg = Regex::new(r"\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]").unwrap();

    reg.replace_all(input, "").to_string()
}

pub fn try_write_file(path: &str, data: &str, append: bool) -> Result<(), String> {
    let mut retry = 3;
    while retry > 0 {
        retry -= 1;

        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .open(path)
        {
            Ok(mut file) => match file.write_all(data.as_bytes()) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if retry <= 0 {
                        return Err(format!("Failed to write to file: {}", e));
                    }
                }
            },
            Err(e) => {
                if retry <= 0 {
                    return Err(format!("Failed to create or open file: {}", e));
                }
            }
        }
    }

    Ok(())
}

fn get_rgb_by_address(addr: &str) -> (u8, u8, u8) {
    let default = vec![0x00, 0x76, 0xff];
    // 8 is the length of `0x` + 3 bytes
    let mut rgb = if addr.len() < 8 {
        default.clone()
    } else {
        hex::decode(&addr[addr.len() - 6..]).unwrap_or(default.clone())
    };
    // ignore black and white
    if rgb[..] == [0x00, 0x00, 0x00] || rgb[..] == [0xff, 0xff, 0xff] {
        rgb = default;
    }

    (rgb[0], rgb[1], rgb[2])
}

fn push_last_input(res: &mut String, input: Option<String>) {
    if input.is_none() {
        return;
    }
    let s = input.unwrap();
    if s.contains("└─") {
        res.push_str(format!("{}\n", s).as_str());
        return;
    }

    let mut parts: Vec<&str> = s.split("├─").collect();
    if let Some(last) = parts.pop() {
        let input = format!("{}└─{}\n", parts.join("├─"), last);
        res.push_str(input.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a `prettify_value` result (`"<int>.<frac> ether"` or `"<int>
    /// ether"` or a bare integer string) back into wei, so the exact
    /// round-trip can be checked against the original value. Kept U256-wide
    /// (unlike the real `parse_pretty_wei`, which is u128-wide -- plenty
    /// for any real ETH funding amount) specifically so this test can also
    /// cover the near-U256-max values below, which exercise
    /// `prettify_value` itself.
    fn parse_pretty_value(s: &str) -> U256 {
        let one_eth = U256::from(10).pow(U256::from(18));
        match s.strip_suffix(" ether") {
            None => U256::from_str_radix(s, 10).unwrap(),
            Some(rest) => match rest.split_once('.') {
                None => rest.parse::<u128>().map(U256::from).unwrap() * one_eth,
                Some((int_part, frac_part)) => {
                    let integer = U256::from_str_radix(int_part, 10).unwrap();
                    let padded = format!("{:0<18}", frac_part);
                    let decimal = U256::from_str_radix(&padded, 10).unwrap();
                    integer * one_eth + decimal
                }
            },
        }
    }

    #[test]
    fn parse_pretty_wei_round_trips_realistic_amounts() {
        // Realistic funding-amount range (parse_pretty_wei is u128-wide,
        // not U256-wide like prettify_value -- see its own doc comment).
        let cases: [u128; 5] = [
            0,
            1,
            999_999_999_999_999,           // just below the " ether" threshold
            5 * 10u128.pow(17),            // 0.5 ether -- exercises trailing-zero trimming
            2_834_308_568_237_875_432_983, // the exact value that surfaced this bug live
        ];
        for value in cases {
            let pretty = prettify_value(U256::from(value));
            assert_eq!(
                parse_pretty_wei(&pretty),
                Some(value),
                "round-trip failed for pretty={pretty}"
            );
        }
    }

    #[test]
    fn prettify_value_round_trips_exactly() {
        let cases = [
            // A near-max-uint256 value (the kind of edge case fuzzing
            // produces) that the old 4-digit truncation silently corrupted.
            U256::from_str_radix(
                "452312848583266388348804605677897579642508237590784484080833333333333333333",
                10,
            )
            .unwrap(),
            U256::from_str_radix("1461501637330902918203684832716283019655932542975", 10).unwrap(),
            // A tiny remainder (5 wei) that the old code rendered as
            // "X.5 ether" (half an ether too much) because it never
            // zero-padded before truncating.
            U256::from(10).pow(U256::from(18)) * U256::from(3) + U256::from(5),
            // Exact multiples of 1 ether must not grow a spurious ".0..." suffix.
            U256::from(10).pow(U256::from(18)) * U256::from(7),
            U256::from(999_999_999_999_999u64), // below the " ether" threshold
        ];

        for value in cases {
            let pretty = prettify_value(value);
            assert_eq!(
                parse_pretty_value(&pretty),
                value,
                "round-trip failed for pretty={pretty}"
            );
        }
    }

    #[test]
    fn prettify_value_small_remainder_is_not_rendered_as_large_fraction() {
        // 5 wei above 3 ether must render as a tiny fraction, not "3.5 ether".
        let value = U256::from(10).pow(U256::from(18)) * U256::from(3) + U256::from(5);
        let pretty = prettify_value(value);
        assert_ne!(pretty, "3.5 ether", "pretty={pretty}");
        assert_eq!(pretty, "3.000000000000000005 ether");
    }
}

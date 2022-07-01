# srcconsole
A rust crate for manipulating the developer console for Source Engine games.

### Features
- log to console (warning, msg)
- run commands (only in 32 bit source engine games, which is most of them)

### Example
```rust
use srcconsole::SourceConsole;

fn main() {
    let console = SourceConsole::new("hl2.exe"); // initialize fn pointers
    console.msg("Rust!"); // print to the console
    console.warning("Warning!");
    console.exec("load quick\n"); // run a command
}
```
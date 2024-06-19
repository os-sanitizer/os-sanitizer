# Examples
Code snippets to highlight reporting by different os-sanitizer passes.

## Prerequisites
1. Make sure `dir1` is writeable by other users. Do it with: `chmod o+w dir1`.
2. Make sure `05_demo_file.txt` is writeable by other users. Do it with `chmod 666 05_demo_file.txt`.

## Usage
1. Build all executables with `make all`.
2. Run individual executable with os-sanitizer running in the background with corresponding option. For example, run `sudo env RUST_LOG=info os-sanitizer --access` in the background and then execute `./01_access`.

## Help with Errors
- To get more details about `errno`: Use `$ errno <errno>`. Installable with `sudo apt install errno`
- Example:
```
$ errno 5
    #define EIO 5
    Input/output error
```

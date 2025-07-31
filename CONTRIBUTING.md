# Contributing to SecurityInfo

First off, thank you for considering contributing to this project! Any and all contributions are welcome.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please open an issue on GitHub. In your issue, please include:

* A clear and descriptive title.
* A detailed description of the bug, including the exact command you ran.
* The expected behavior and what actually happened.
* Any relevant error messages or logs.
* The version of the module you are using.

### Suggesting Enhancements

If you have an idea for an enhancement, please open an issue on GitHub. In your issue, please include:

* A clear and descriptive title.
* A detailed description of the proposed enhancement and why it would be useful.
* Any examples of how the enhancement would be used.

### Pull Requests

If you would like to contribute code, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes. Please ensure you follow the existing code style.
4. Add new functions to the `functions` directory.
5. Update the module manifest (`SecurityInfo.psd1`) if necessary (e.g., exporting new functions).
6. Submit a pull request with a clear description of your changes.

## Development Setup

This project is a PowerShell module. All functions are located in the `functions` directory. The main module file, `SecurityInfo.psm1`, loads all functions from this directory.

When adding a new function, create a new `.ps1` file in the `functions` directory. The name of the file should be the same as the name of the function.

Thank you for your contribution!

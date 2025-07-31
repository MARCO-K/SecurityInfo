# Testing Guide

## Overview

The SecurityInfo module includes comprehensive Pester tests covering all functions with 137 test cases achieving 100% pass rate.

## Running Tests

### All Tests

```powershell
Invoke-Pester -Path "tests\" -Output Normal
```

### Individual Function Tests

```powershell
# Test individual functions
Invoke-Pester -Path "tests\Get-NvdCve.Tests.ps1" -Output Detailed
Invoke-Pester -Path "tests\Get-CveOrg.Tests.ps1" -Output Detailed
Invoke-Pester -Path "tests\Get-SecurityInfo.Tests.ps1" -Output Detailed
```

### Test Coverage

- **Get-CisaKev**: 16 tests - Basic functionality, error handling, data validation
- **Get-CveOrg**: 17 tests - API integration, cross-platform compatibility
- **Get-EpssScore**: 15 tests - Score validation, bulk operations
- **Get-EUvd**: 18 tests - EU vulnerability database integration
- **Get-ExploitDb**: 17 tests - Exploit database queries
- **Get-GitHubSecurityAdvisory**: 21 tests - GitHub security advisories
- **Get-NvdCve**: 36 tests - Comprehensive NVD integration
- **Get-SecurityInfo**: 33 tests - Meta-function aggregation and orchestration

## Test Structure

Each test file includes:

- Mocked external API calls for reliability
- Error condition testing
- Data type validation
- Edge case handling
- Performance validation

## Compatibility

Tests are compatible with:

- Windows PowerShell 5.1
- PowerShell 7.x
- Cross-platform execution

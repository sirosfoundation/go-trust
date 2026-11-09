# Multi-Registry Combination with CompositeRegistry

This document describes how to combine responses from multiple trust registries using the `CompositeRegistry` pattern in the go-trust framework.

## Overview

The go-trust framework supports flexible trust policies by treating **registries as composable building blocks**. The `CompositeRegistry` implements the `TrustRegistry` interface while wrapping other registries with boolean logic (AND/OR/MAJORITY/QUORUM). This enables arbitrarily complex trust policies through nesting, such as `"(A OR B) AND (C OR D)"`.

## Architecture

### Key Insight: Registries as Virtual Registries

Rather than adding complex strategy logic to the `RegistryManager`, we treat combination logic itself as a registry. This provides:

- **Composability**: Registries are building blocks that can be nested arbitrarily
- **Uniformity**: Everything is just a `TrustRegistry` - no special cases
- **Simplicity**: `RegistryManager` stays simple (FirstMatch, Sequential, etc.)
- **Testability**: Each composite can be tested in isolation

### RegistryManager Strategies (Simple Routing)

The `RegistryManager` coordinates registered registries using simple routing strategies:

- **FirstMatch** (default): Query registries in parallel, return first positive match (fastest, OR with fast exit)
- **AllRegistries**: Query all registries and collect results (complete audit trail)
- **BestMatch**: Query all and return highest confidence match
- **Sequential**: Try registries in registration order until success (for rate-limited APIs)

### CompositeRegistry (Boolean Logic)

The `CompositeRegistry` combines child registries using boolean operators:

- **LogicAND**: ALL children must return `decision=true`
- **LogicOR**: At least ONE child must return `decision=true`
- **LogicMAJORITY**: More than 50% of children must agree
- **LogicQUORUM**: Configurable threshold (e.g., 2 of 3 must agree)

## Usage Examples

### Example 1: Simple AND (Defense in Depth)
**Requirement**: Trust only if BOTH ETSI-TSL AND OpenID Federation approve

```go
// Create individual registries
etsiRegistry := etsi.NewETSITSLRegistry(etsiConfig)
oidfRegistry := oidfed.NewOIDFRegistry(oidfConfig)

// Combine with AND logic
composite := registry.NewCompositeRegistry(
    "defense-in-depth",
    registry.LogicAND,
    etsiRegistry,
    oidfRegistry,
)

// Register the composite registry
manager := registry.NewRegistryManager(registry.FirstMatch, 5*time.Second)
manager.Register(composite)
```

### Example 2: Simple OR
**Requirement**: Trust if ANY of the validators approve

```go
composite := registry.NewCompositeRegistry(
    "any-validator",
    registry.LogicOR,
    validator1,
    validator2,
    validator3,
)
```

### Example 3: Quorum Voting
**Requirement**: Trust if at least 2 of 3 validators agree

```go
composite := registry.NewCompositeRegistryWithOptions(
    "quorum-validators",
    registry.LogicQUORUM,
    []registry.TrustRegistry{validator1, validator2, validator3},
    registry.WithThreshold(2),
)
```

### Example 4: Complex Nesting - (A OR B) AND C
**Requirement**: Trust if (ETSI-TSL OR Custom-Validator) AND OpenID-Federation

```go
// Create OR group for European validators
euValidators := registry.NewCompositeRegistry(
    "eu-validators",
    registry.LogicOR,
    etsiRegistry,
    customValidator,
)

// Create AND combining EU validators with federation check
finalPolicy := registry.NewCompositeRegistry(
    "main-policy",
    registry.LogicAND,
    euValidators,
    oidfRegistry,
)

manager.Register(finalPolicy)
```

### Example 5: Deep Nesting - ((A AND B) OR C) AND (D OR E)
**Requirement**: Complex multi-layer policy

```go
// Layer 1: A AND B
group1 := registry.NewCompositeRegistry("group1", registry.LogicAND, regA, regB)

// Layer 2: (A AND B) OR C
group2 := registry.NewCompositeRegistry("group2", registry.LogicOR, group1, regC)

// Layer 3: D OR E
group3 := registry.NewCompositeRegistry("group3", registry.LogicOR, regD, regE)

// Final: ((A AND B) OR C) AND (D OR E)
final := registry.NewCompositeRegistry("final", registry.LogicAND, group2, group3)
```

## CompositeRegistry API

### Constructor

```go
func NewCompositeRegistry(name string, operator LogicOperator, registries ...TrustRegistry) *CompositeRegistry
```

### With Options

```go
func NewCompositeRegistryWithOptions(
    name string,
    operator LogicOperator,
    registries []TrustRegistry,
    opts ...CompositeOption,
) *CompositeRegistry

// Options:
registry.WithThreshold(2)                          // For LogicQUORUM
registry.WithTimeout(10*time.Second)               // Timeout for child evaluations
registry.WithDescription("Custom description")     // Human-readable description
```

### Operators

```go
const (
    LogicAND      LogicOperator = "AND"       // All must agree
    LogicOR       LogicOperator = "OR"        // At least one must agree
    LogicMAJORITY LogicOperator = "MAJORITY"  // >50% must agree
    LogicQUORUM   LogicOperator = "QUORUM"    // Threshold must agree (set via WithThreshold)
)
```

## Response Context

CompositeRegistry returns rich context information:

```json
{
  "decision": true,
  "context": {
    "reason": {
      "registry": "defense-in-depth",
      "operator": "AND",
      "total_registries": 2,
      "agreed_count": 2,
      "disagreed_count": 0,
      "error_count": 0,
      "agreed_registries": ["ETSI-TSL", "OpenID-Federation"],
      "disagreed_registries": [],
      "requires_all": true,
      "details": [
        {
          "registry": "ETSI-TSL",
          "type": "etsi_tsl",
          "decision": true,
          "duration_ms": 45
        },
        {
          "registry": "OpenID-Federation",
          "type": "oidf",
          "decision": true,
          "duration_ms": 32
        }
      ]
    }
  }
}
```

## Distinguishing "could not evaluate" from "not trusted"

Both outcomes are `decision: false`, so clients that read only `decision` are unaffected. When
a denial is not a trust verdict, `context.reason` also carries:

```json
{
  "decision": false,
  "context": {
    "reason": {
      "evaluation_status": "error",
      "evaluation_errors": [{"registry": "etsi", "error": "circuit breaker open"}]
    }
  }
}
```

`evaluation_status: "error"` is set when at least one applicable registry failed to answer:
the registry returned an error, timed out, panicked, was skipped because its circuit breaker
is open, or is a composite with a failed child. A registry that failed might have trusted
the subject, so the denial is not final even if another registry answered "no". The member is
absent when every applicable registry answered (an *evaluated: not trusted* verdict) and on
every allow (a positive match stands even if another registry failed). The same rule applies
to all four strategies (`first_match`, `all`, `best_match`, `sequential`).

Callers that fall back to a different policy only on failure (never on a denial) should test
`evaluation_status == "error"`; in Go, use `EvaluationResponse.CouldNotEvaluate()`. A registry
that reports an internal problem as an ordinary denial (rather than an error) is not covered.

## Integration with RegistryManager

CompositeRegistry implements `TrustRegistry`, so it works seamlessly with RegistryManager:

```go
// Mix composite and individual registries
manager := registry.NewRegistryManager(registry.FirstMatch, 5*time.Second)

// Add a composite policy
policy1 := registry.NewCompositeRegistry("policy1", registry.LogicAND, reg1, reg2)
manager.Register(policy1)

// Add individual registries as fallbacks
manager.Register(reg3)
manager.Register(reg4)

// FirstMatch strategy tries policy1 first, then reg3, then reg4
```

## Performance Considerations

- **Parallel Evaluation**: CompositeRegistry evaluates all child registries in parallel
- **Timeout Control**: Set timeout via `WithTimeout()` option
- **Circuit Breakers**: Child registries maintain their own circuit breakers
- **Nesting Depth**: Each nesting level adds latency (parallel within each level)

## Use Case Patterns

### High Security (AND)
```go
// Require multiple independent validations
composite := registry.NewCompositeRegistry("high-sec", registry.LogicAND,
    etsiTSL, oidfed, enterpriseValidator)
```

### Fallback Chain (OR)
```go
// Try primary, fall back to secondary
composite := registry.NewCompositeRegistry("fallback", registry.LogicOR,
    primaryRegistry, secondaryRegistry)
```

### Consensus (MAJORITY)
```go
// Democratic decision from multiple validators
composite := registry.NewCompositeRegistry("consensus", registry.LogicMAJORITY,
    validator1, validator2, validator3, validator4, validator5)
```

### Flexible Threshold (QUORUM)
```go
// Custom threshold: "3 of 5 must agree"
composite := registry.NewCompositeRegistryWithOptions("quorum", registry.LogicQUORUM,
    []registry.TrustRegistry{v1, v2, v3, v4, v5},
    registry.WithThreshold(3))
```

### Geo-Distributed (Nested OR/AND)
```go
// (EU-Validator-A OR EU-Validator-B) AND (US-Validator-A OR US-Validator-B)
euGroup := registry.NewCompositeRegistry("eu", registry.LogicOR, euA, euB)
usGroup := registry.NewCompositeRegistry("us", registry.LogicOR, usA, usB)
geoPolicy := registry.NewCompositeRegistry("geo", registry.LogicAND, euGroup, usGroup)
```

## Benefits Over Strategy-Based Approach

**Before (Strategy-based)**:
- Complex strategy routing in RegistryManager
- Strategies hardcoded in manager
- Limited nesting capability
- Special configuration for groups

**After (CompositeRegistry)**:
- ✅ RegistryManager stays simple
- ✅ Infinite nesting through composition
- ✅ Each composite independently testable
- ✅ No special configuration - just registries

## Testing

```go
// Test composite logic independently
func TestComposite(t *testing.T) {
    reg1 := &MockRegistry{decision: true}
    reg2 := &MockRegistry{decision: false}

    composite := registry.NewCompositeRegistry("test", registry.LogicAND, reg1, reg2)

    resp, _ := composite.Evaluate(ctx, req)
    // Should be false (AND requires all)
}
```

## Future Enhancements

Potential additions:
- **Weighted voting**: Different weights for different registries
- **Async evaluation**: Don't wait for slow registries in OR logic
- **Caching**: Cache composite results
- **DSL/Config**: Define composite policies in YAML/JSON


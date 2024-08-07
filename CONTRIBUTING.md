# Contributing

Thank you for contributing to NEBRA's `upa`! Here are some guidelines to follow when adding code or documentation to this repository.

## Rust

When contributing to the rust crates, `circuits` and `prover`, please adhere to the following rules

### The `Cargo.toml` File

The `Cargo.toml` file should ahere to the following template:

```toml
[package]
name = "..."
version = "..."
edition = "..."

[dependencies]
...

[dev-dependencies]
...

[build-dependencies]
...

[features]
...

[[bin]]
...

[[bench]]
...
```

For a given dependency use the following structure with `features` keys as needed:
```toml
    crate-name = { version = "...", optional = true, default-features = false, features = ["..."] }
```
In the case of `git` dependencies:
```toml
    crate-name = { git = "...", tag = "...", default-features = false, features = ["..."] }
```
It is preferred to use `tag` over `rev` and `rev` over `branch`.

### Imports and Exports

Imports (`use`) and exports (`mod`) should be ordered as follows:

1. External Crate Declarations
2. Private Imports
3. Private Imports with Features
4. Reexports
5. Reexports with Features
6. Private Exports
7. Private Exports with Features
8. Public Exports
9. Public Exports with Features

Here's an example set of declarations:

```rust
extern crate crate_name;

use module::submodule::entry;

#[cfg(feature = "...")]
use module::feature_gated_submodule;

pub use reexported_objects;

#[cfg(feature = "...")]
pub use feature_gated_reexported_objects;

mod another_module;
mod module;
mod the_third_module;

#[cfg(feature = "...")]
mod feature_gated_module;

pub mod public_module;

#[cfg(feature = "...")]
pub mod feature_gated_public_module;
```

Ensure that there are newlines between each category. Be sure that if there are imports or exports that are feature-gated, that they are sorted by feature alphabetically. If there is a feature gated import that requires importing multiple objects use the following pattern:

```rust
#[cfg(feature = "...")]
use {
    thing1, thing2, thing3, thing4,
};
```

**NOTE**: All imports should occur at the top of any module and a newline should be added between the last import and the first declared object.

### Traits

#### Defining Traits

When defining a trait use the following syntax:

```rust
/// DOCS
trait Trait<T> {
    /// DOCS
    type Type1: Default;

    /// DOCS
    type Type2;

    /// DOCS
    const CONST_1: usize;

    /// DOCS
    const CONST_2: usize;

    /// DOCS
    fn required_method(&self, argument: Self::Type1) -> T;

    /// DOCS
    fn optional_method(&self) -> T {
        Self::required_method(Self::Type1::default())
    }
}
```

Notice the ordering of components:

1. Associated Types
2. Associated Constants
3. Methods

Depending on the context and presentation, you can mix the ordering of required and optional methods. Also, notice the name formatting, although `clippy` should detect if naming differs from this pattern.

#### Implementing Traits

When implementing traits use the following syntax:

```rust
impl<T> Trait for Struct<T> {
    type Type1 = B;
    type Type2 = C;

    const CONST_1: usize = 3;
    const CONST_2: usize = 4;

    fn required_method(&self, argument: Self::Type1) -> T {
        self.struct_method(argument).clone()
    }

    fn optional_method(&self) -> T {
        short_cut_optimization(self)
    }
}
```

Notice the lack of space between implementaions of the same category except for methods which always get a newline between them (like all methods). Only add space between types and constants if a comment is necessary like in this example:

```rust
impl Configuration {
    const SPECIAL_CONSTANT: usize = 1234249;

    /// In this case we have to use this constant because it's very special.
    const ANOTHER_SPECIAL_CONSTANT: usize = 10000023;
}
```

but otherwise it should look like

```rust
impl Configuration {
    const SPECIAL_CONSTANT: usize = 1234249;
    const ANOTHER_SPECIAL_CONSTANT: usize = 10000023;
}
```

### Ignoring Compiler Warnings

In certain cases we may want to ignore a particular compiler warning or `clippy` warning. This is especially true in because of some false-positive error or because we are writing some generic macro code. In either case we need to mark the `#[allow(...)]` clause with a note on why we want to ignore this warning. 

```rust
#[allow(clippy::some_lint)] // NOTE: Here's the reason why this is ok.
fn some_function() {}
```

In the case of `allow` we want to be careful of it's scope so as to not ignore warnings except in the exact place where the unexpected behavior exists. Therefore, `#[allow(...)]` should be marked on functions and not modules, even if that means it is repeated multiple times. In some rare cases where this repetition would be too cumbersome, and adding it to the module is cleaner, then also be sure to state in a note why this is better than marking it on the functions themselves.

### Where Clauses

1. Use inline trait constraints when there is a single generic type and a single constraint, e.g.

    ```rust
    fn function<T: Clone>(t: &T) -> T {
        t.clone()
    }
    ```

2. In all other cases, always use where clauses instead of inline trait constraints. So instead of

    ```rust
    fn function<T: Clone + Debug>(t: &T) -> T {
        println!("{t:?}");
        t.clone()
    }
    ```

    you should use

    ```rust
    fn function<T>(t: &T) -> T
    where
        T: Clone + Debug,
    {
        println!("{t:?}");
        t.clone()
    }
    ```

    This is also true for any part of the code where generic types can be declared, like in `fn`, `struct`, `enum`, `trait`, and `impl`. The only "exception" is for supertraits, so use:

    ```rust
    trait Trait: Clone + Default + Sized {}
    ```

    instead of using

    ```text
    trait Trait
    where
        Self: Clone + Default + Sized,
    {}
    ```

3. Order `where` clause entries by declaration order, then by associated types and then by other constraints. Here's an example

    ```rust
    fn function<A, B, C>(a: &A, b: &mut B) -> Option<C>
    where
        A: Clone + Iterator,
        B: Default + Eq,
        C: IntoIterator,
        A::Item: Clone,
        C::IntoIter: ExactSizeIterator,
        Object<B, C>: Copy,
    ```

    **NOTE**: This rule is not so strict, and these `where` clauses should be organized in a way that makes most sense but must follow this general rule.

4. Order each entries constraints alphabetically. Here's an example:

    ```rust
    F: 'a + Copy + Debug + FnOnce(T) -> S
    ```

    The ordering should be lifetimes first, then regular traits, then the function traits.


### Magic Numbers

In general, we should avoid magic numbers and constants in general but when they are necessary, they should be declared as such in some module instead of being used in-line with no explanation. Instead of

```rust
/// Checks that all the contributions in the round were valid.
pub fn check_all_contributions() -> Result<(), ContributionError> {
    for x in 0..7 {
        check_contribution(x)?;
    }
    Ok(())
}
```

you should use

```rust
/// Contribution Count for the Round-Robin Protocol
pub const PARTICIPANT_COUNT: usize = 7;

/// Checks that all the contributions in the round were valid.
pub fn check_all_contributions() -> Result<(), ContributionError> {
    for x in 0..PARTICIPANT_COUNT {
        check_contribution(x)?;
    }
    Ok(())
}
```

Avoid situations where an arbitrary number needs to be chosen, and if so prefer empirically measured numbers. If for some reason an arbitrary number needs to be chosen, and it should have a known order of magnitude, chose a power of two for the arbitrary number, or something close to a power of two unless the situation calls for something distinctly _not_ a power of two.

### Unsafe rust

Unsafe rust is discouraged. When used, you must provide a complete explanation why undefined behaviour won't happen. For example:
```rust
fn safe_wrapper_of_unsafe_function() {
    // The code below is unsafe because [...] and if it's called
    // when [...] it can lead to undefined behaviour. However, here
    // we make sure that the argument satisfies [...] which rules 
    // out such behaviour because [...].
    unsafe {
        ...
    } 
}
```

### Comments and Documentation

In general, documentation should be added on function/interface boundaries instead of inside code blocks which should be written in a way that explains itself. Sometimes however, we have to do something specific that is counter-intuitive or against some known principle in which case we should comment the code to explain ourselves.

**IMPORTANT**: Documentation should explain _what_ behavior an interface provides, and comments explain _how_ the implementation provides this behavior.

When formatting comments we have a few comment types:

1. `NOTE`: Explains some unintuitive behavior or makes note of some invariants that are being preserved by this particular piece of code.
2. `TODO`: Like `NOTE`, but involves relaying the information relevant for a fix or future optimization.
3. `FIXME`: Something is critically broken or inconveniently written and should be changed whenever possible.

Here are some important guidelines to follow for general documentation:

1. All module documentation should exist in the module itself in the header with `//!` doc strings.
2. Documentation is mandatory for all public-facing interfaces, e.g. `pub struct`, `pub trait`, `pub fn`, `pub const`. It is not mandatory, but recommended for private ones.
3. Be sure to link all documentation that refers to objects in the code.
4. Function documentation should be in present tense. It should answer the question "What does this function do?".
5. The right order is: first docs, then macros, then the object.
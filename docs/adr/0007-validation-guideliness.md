# How we are going to validate the new API codebase

* Date: 2021-03-10

Technical Story:
- [securesystemslib schema checker issues](https://github.com/secure-systems-lab/securesystemslib/issues/183)
- [new TUF validation guidelines](https://github.com/theupdateframework/tuf/issues/1130)

## Context and Problem Statement

1. Some schemas sound more specific than they are.
2. Some schemas are an odd replacement for constants.
3. Schema validation is generally **overused**. Together with user input,
we are validating input programmatically generated from our private functions.
4. There are instances where some attributes are validated multiple times
when executing one API call.
5. Schema checking sometimes makes execution branches unreachable.
6. The error messages from checking schemas are often not helpful.

## Decision Drivers and Requirements
Some of the requirements we want to meet are:
1. The ability to decide which functions to validate and which not.
2. Allow for custom deeper validation beyond type check.
3. As little as possible performance overhead.
4. Add as minimal number of dependencies as possible.
5. Support for all python versions we are using.

## Considered Options
1. Usage of a `ValidationMixin`.
2. Usage of a third-party library called `pydantic`.

## Pros, Cons, and Considerations of the Options

### Option 1: Usage of a ValidationMixin

**Note:** All pros, cons, and considerations are documented with the assumption
we would implement the `ValidationMixin` the same way it is implemented in
[in-toto](https://github.com/in-toto) until version 1.0.1 (the latest
version at the time of writing.)

* Good, because it's shorter by calling one function and validating
multiple fields.

* Good, because it allows reuse of the validation code through
`securesystemslib.schemas` or another schema of our choice.

* Bad, because there could be different code paths and return statements, and as
a consequence there could be a code path which doesn't call `validate()`.

Examle:
```python
class User(ValidationMixin):

  def __init__(self, id: int, nickname: str) -> None:
      self.id = id
      self.nickname = nickname
      self.pro_user = False

      self.validate()

  def _validate_id(self):
    if not isinstance(self.id, int):
          raise FormatError(f'id should be from type int')

    if self.id < 0:
      raise ValueError(f'id is expected to be a positive number')

  def update_profile(self, new_id: int, new_nickname: str):
    self.id = new_id

    if not self.pro_user:
      print(f'Standart users can only change their id! '
            f'If you want to change your nickname become a pro user.)

      return

    self.nickname = new_nickname
    # Be careful if you rely on _validate_id() to verify self.id!
    # This won't be called if new_name is "".
    self.validate()
```

* *Personal opinion*: bad, because it's not a clean solution from an OOP
perspective to inherit `ValidationMixin` from classes without a "IS A"
relationship with it.

* Consideration: if we use this option, we are limited on what can be validated.
With the `in-toto` implementation of the `ValidationMixin`, we can only validate
class attributes inside class methods.
If we want to validate functions outside classes or function arguments we would
have to enhance this solution.

* Consideration: if we use this option, we would be responsible for the code
and all identified issues related to `securesystemslib.schemas` should be
resolved by us or replace the schema implementation with something else.

* Consideration: if we want to enforce assignment validation, this solution
should be combined with custom "setter" properties.

### Option 2: Usage of a third-party library called "pydantic"

* Good, because it's flexible:
1. There is a `@validate_arguments` decorator which allows us to decide which
functions to validate and the ability to validate functions outside classes.
2. There is a `@validator` decorator which allows us to make a deeper validation
beyond type checking for our class attributes.
3. We can use an embedded `Config` class inside our classes, which allows for
even more customization (for example enforce assignment validation).

* Good, because (according to their documentation) `pydantic` is the fastest
validation library compared to others (including our other third-party library
option `marshmallow`).
See: https://pydantic-docs.helpmanual.io/benchmarks/

* Good, because it uses the built-in types from `python 3.6` onwards.

* Bad, because this library **has not yet implemented** a `strict` mode and
the default behaviour when validating a certain argument or field is to **try
a cast to the expected type from the received type**.
To enable strict mode, we would have to add this manually through
`validators` that are called before the cast.
See: https://github.com/samuelcolvin/pydantic/issues/1098

* Bad, because there is a learning curve when using `pydantic`.
1. For example, when I had to handle the `_type` attribute in `Signed` it took me
a lot of reading to understand that standard attributes whose name begin with
"_" are ignored. The `_type` attribute can only be `PrivateAttr`
(defined in `pydantic`) even though we don't handle it as a typical private
attribute.
2. Also, I had difficulties using pydantic when there is inheritance.
The initialization and validation of new objects was tricky.

* Bad, because it adds `2` new dependencies: `pydantic` and `typing-extensions`.
This was concluded by performing the following steps:
1. Creating a fresh virtual environment with python3.8.
2. Installing all dependencies in `requirements-dev.txt` from `tuf`.
3. Install `pydantic` with `pip install pydantic`.

## Links
* [in-toto ValidatorMixin](https://github.com/in-toto/in-toto/blob/74da7a/in_toto/models/common.py#L27-L40)
* [ValidatorMixing usage](https://github.com/in-toto/in-toto/blob/74da7a/in_toto/models/layout.py#L420-L438)
* [Pydantic documentation](https://pydantic-docs.helpmanual.io/)

## Decision Outcome

*TODO: Make and describe the decision*

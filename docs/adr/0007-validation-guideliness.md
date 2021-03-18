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
6. Reuse code used for validation.
7. A way to invoke all validation functions responsible to validate the class
attributes in the middle of function execution.

## Considered Options
1. Usage of a `ValidationMixin`.
2. Usage of a third-party library called `pydantic`.
3. Usage of a third-party library called `marshmallow`.

## Pros, Cons, and Considerations of the Options

### Option 1: Usage of a ValidationMixin

**Note:** All pros, cons, and considerations are documented with the assumption
we would implement the `ValidationMixin` the same way it is implemented in
[in-toto](https://github.com/in-toto) until version 1.0.1 (the latest
version at the time of writing.)

Here is how this option compares against our
[requirements](#decision-drivers-and-requirements):

| Number      | Stance |
| ----------- | ----------- |
| 1 | It's limited on what it can validate.  |
| 2   | Yes, it does allow that. |
| 3   | It contains only the code we need, so the overhead is minimal. |
| 4   | It doesn't add any dependencies.        |
| 5   | Yes, it does support all of our python versions.      |
| 6   | Yes, it does allow that.  |
| 7   | Yes, it does allow that. |

Additional thoughts:

* Bad, because there could be different code paths and return statements, and as
a consequence there could be a code path that doesn't call `validate()`.

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

* Consideration (*related to point 1*): if we use this option, we are limited on
what can be validated.
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

Here is how this option compares against our
[requirements](#decision-drivers-and-requirements):

| Number      | Stance |
| ----------- | ----------- |
| 1 | It's not limited to what it can validate.  |
| 2   | Yes, it allows that through a `@validator` decorator. |
| 3   | The fastest validation library according to [them](https://pydantic-docs.helpmanual.io/benchmarks/).  |
| 4   | It adds two dependencies. |
| 5   | Yes, it does support all of our python versions. |
| 6   | Yes, it does allow that.  |
| 7   | It allows it, but with not very intuitive manner.  |

Additional thoughts:

* Good, because it's flexible:
1. There is a `@validate_arguments` decorator which allows us to decide which
functions to validate and the ability to validate functions outside classes.
2. There is a `@validator` decorator which allows us to make a deeper validation
beyond type checking for our class attributes.
3. We can use an embedded `Config` class inside our classes, which allows for
even more customization (for example enforce assignment validation).

* Good, because it allows for strict type checks through `StrictInt`, `StrictStr`,
`StrictFloat`, `StrictBool` and `StrictBytes` types defined in `pydantic` .
They have not yet implemented a classwide strict mode where all fields will be
considered automatically as "strict", but there is a discussion about it:
See: https://github.com/samuelcolvin/pydantic/issues/1098

* Good, because it provides additional custom types (with their own built-in
validation) like `FilePath`/`DirectoryPath` (like `typing.Path`, but there is also
validation that the file/directory exists), `PostivieInt`, `IPvAnyAddress`
(for IP versions 4 and 6), `HttpUrl` (for HTTP and HTTPS URLs) etc.
Also, `pydantic` has field (class attributes) constraints. This could be useful
when verifying that a HEX string has the expected length.

* Good, if we decide to require that our objects should be valid and fully
populated all of the time. This could easily be marking our fields (class
attributes) as `required` (which will raise an error for partially populated
objects) and embed a `Config` class inside our classes with an option to enforce
assignment validation.

* Bad, because there is a learning curve when using `pydantic`.
1. For example, when I had to handle the `_type` attribute in `Signed` it took me
a lot of reading to understand that standard attributes whose name begin with
"_" are ignored. The `_type` attribute can only be `PrivateAttr`
(defined in `pydantic`) even though we don't handle it as a typical private
attribute.
2. Also, I had difficulties using `pydantic` when there is inheritance.
The initialization and validation of new objects was tricky.

* Bad, because it adds `2` new dependencies: `pydantic` and `typing-extensions`.
This was concluded by performing the following steps:
1. Creating a fresh virtual environment with python3.8.
2. Installing all dependencies in `requirements-dev.txt` from `tuf`.
3. Install `pydantic` with `pip install pydantic`.

* Explanation about requirment number 7: there is a helper function called
`validate_model(model: Type[BaseModel], input_data: DictStrAny)` which can be
used to invoke all validators from your current or parent classes.
This is how it can be used:
```python
class User(BaseModel):
  email: StrictStr

  @validator('email')
  def validate_email(cls, email):
    # Some regular expression checks for a valid email here
    return email

  def change_email(self, new_email: StrictStr):
    self.email = new_email


class RepositoryManager(BaseModel):
  repositoryUsers: List[User]
  writer: object

  def validate(self):
    *_, validation_error = validate_model(self.__class__, self.__dict__)
    if validation_error:
        raise validation_error

  def write_users_to_file(self):
    for user in self.repositoryUsers:

      # Validate that user objects have valid fields before writing
      # even if their email has changed.
      user.validate()

    self.writer.write_to_file(self.repositoryUsers)
```

### Option 3: Usage of a third-part library called "marshmallow"

Here is how this option compares against our
[requirements](#decision-drivers-and-requirements):

| Number      | Stance |
| ----------- | ----------- |
| 1 | It can validate only class attributes.  |
| 2   | Yes, it allows that. |
| 3   | Likely slower than `pydanitc` (according to [pydantic](https://pydantic-docs.helpmanual.io/benchmarks/)).  |
| 4   | It adds 1 additional dependency. |
| 5   | Yes, it does support all of our python versions. |
| 6   | Yes, it does allow that.  |
| 7   | Yes, it allows that through `validate()` function. |

Additional thoughts:

* Good, because it allows for strict type checks by marking the class attributes
(or Fields as they call them) as `strict`.

* Good, because it provides additional custom types (with their own built-in
validation) like `URL`, `IPv4`, `IPv6`, etc.

* Bad, because it's created with schemas in mind and a heavy focus on
serialization and deserialization. Most of the features are not related
to validation.

* Bad, because it adds one additional dependency - itself.
This was concluded by performing the following steps:
1. Creating a fresh virtual environment with python3.8.
2. Installing all dependencies in `requirements-dev.txt` from `tuf`.
3. Install `marshmallow` with `pip install marshmallow`.

* Bad, because they use their custom types even for types existing in the
standard `typing` module from python 3.6 onwards. This means that integrating
`marshmallow` would make up for a bigger diff compared to `pydantic`.
Additionally, because they define their types there could be problems specific
to their types and conversion from-to standard types as defined in the `typing`
python module.
This was the case when I researched `marshmallow` and had to use the
`marshmallow.fields.DateTime` class instead of the `datetime.datetime` object.



## Links
* [in-toto ValidatorMixin](https://github.com/in-toto/in-toto/blob/74da7a/in_toto/models/common.py#L27-L40)
* [ValidatorMixing usage](https://github.com/in-toto/in-toto/blob/74da7a/in_toto/models/layout.py#L420-L438)
* [Pydantic documentation](https://pydantic-docs.helpmanual.io/)
* [Marshmallow documentation](https://marshmallow.readthedocs.io/)

## Decision Outcome

*TODO: Make and describe the decision*

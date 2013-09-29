# journal-triggerd -- Runs trigger on journal messages

**journal-triggerd** is a small daemon that runs in the background, listening to
systemd's journal, and will run "triggers" (i.e. exec a command line) when
certain messages are added.

You can define which messages to listen for, and what to run when such messages
are added to the journal, by defining simple text file rules.

Rules can use boolean logic with groups of conditions, e.g. `foobar AND (foo OR
NOT bar)` where each group (foo, bar, etc) is simply another section in the file,
which can include as many conditions as needed.

All conditions are simply the name of a field from the journal, an optional
comparison operator before the required equal sign ('='), and the value to
compare with.

The supported operators are :

* **Exact match: =**

The field must be of the specified value.

* **Pattern match: ?**

You can use '\*' and '?' wildcards with similar semantics as the standard glob(3)
functions: '\*' matches an arbitrary, possibly empty, string, '?' matches an
arbitrary character.

Note that in contrast to glob(), the '/' character can be matched by the
wildcards, there are no '[...]' character ranges and '\*' and '?' can not be
escaped to include them literally in a pattern.

* **Lesser match: <**

The value must be an integer, the value of the field will also be parsed as an
integer value, and must be less than or equal to the specified value to match.

* **Greater match: >**

The value must be an integer, the value of the field will also be parsed as an
integer value, and must be greater than or equal to the specified value to match.


You can specify as many conditions as you want in each group; All will need to
be a match for the entire group to be a match. You can specify conditions on the
same field multiple times.

It is also possible to prefix the comparison operator with a '!' in order to
inverse the match, i.e. the field shall not match the condition for it to be a
match.

## Want to know more?

Some useful links if you're looking for more info:

- [blog post about journal-triggerd](http://jjacky.com/journal-triggerd "journal-triggerd @ jjacky.com")

- [source code & issue tracker](https://github.com/jjk-jacky/journal-triggerd "journal-triggerd @ GitHub.com")

- [PKGBUILD in AUR](https://aur.archlinux.org/packages/journal-triggerd/ "AUR: journal-triggerd")

Plus, journal-triggerd comes with a man page.

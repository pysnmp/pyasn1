
Continuous integration and releases
===================================

This page describes how changes reach a released version of
``pysnmp-pyasn1``. The same model is used by
`pysmi <https://github.com/pysnmp/pysmi>`_ and
`pysnmp <https://github.com/pysnmp/pysnmp>`_, so what follows applies to
all three projects except where a difference is called out.

Branches
--------

There are exactly two long-lived branches.

``next``
    Where work integrates. Every pull request targets ``next``. It is
    normal and expected for ``next`` to carry commits that ``main`` does
    not.

``main``
    What has been released. It moves only when ``next`` is promoted into
    it.

Maintenance branches matching ``N.x`` or ``N.M.x`` are configured but none
exist yet.

Do not open a pull request against ``main``. A fix merged there would be
released without ever having existed as a release candidate, and ``next``
would not contain it.

Neither branch releases on push. Both the release candidate and the GA are
cut by a human dispatching the workflow; see `Cutting a release`_.

Commit messages
---------------

Releases are cut by `semantic-release
<https://semantic-release.gitbook.io/>`_ from the commit history, so the
subject line of every commit decides whether a release happens and how the
version changes.

The `Conventional Commits <https://www.conventionalcommits.org/>`_
``conventionalcommits`` preset is in use:

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Subject
     - Version change
     - Appears in release notes
   * - ``fix: ...``
     - patch
     - Bug Fixes
   * - ``feat: ...``
     - minor
     - Features
   * - ``perf: ...``
     - patch
     - Performance Improvements
   * - ``feat!: ...``
     - **major**
     - Features, and BREAKING CHANGES
   * - ``BREAKING CHANGE:`` footer
     - **major**
     - BREAKING CHANGES
   * - ``docs:``, ``test:``, ``ci:``, ``chore:``, ``refactor:``, ``style:``
     - none
     - hidden

The ``!`` marker and the ``BREAKING CHANGE:`` footer are equivalent. Note
that the *angular* preset, which is semantic-release's default, does not
parse ``!`` at all — a ``feat!:`` commit under that preset silently
produces a minor release rather than a major one. All three projects set
``conventionalcommits`` explicitly for this reason.

Reference an issue in the body (``Closes #123``) rather than in the
subject, so the generated notes link it.

What runs on a pull request
---------------------------

The ``CI`` workflow (``.github/workflows/build-test-release.yml``) runs on
every push to ``main`` and ``next`` and on every pull request against
them.

``pre-commit``
    The repository's ``pre-commit`` hooks, on every file.

``lint``
    ``ruff check``, ``ruff format --check`` and ``mypy``. ``ty`` also runs
    but is advisory: it is pre-1.0 and has no equivalent of
    ``disallow_untyped_defs``, so ``mypy`` remains the blocking gate.

``docs``
    ``sphinx-build -W --keep-going``. Warnings are errors, and
    ``--keep-going`` reports all of them rather than stopping at the
    first.

``build``
    ``uv build``, uploading the wheel and sdist as an artifact.

``matrix``
    Computes the test matrix. See below.

``test-unit``
    The test suite, once per matrix entry, publishing JUnit results and
    coverage.

``Build Release``
    Runs semantic-release. On a pull request this job does not run at
    all; on a push it rehearses the release without cutting one.

The test matrix
---------------

Every supported Python runs on Linux on every pull request. macOS and
Windows run only on the edge Python versions, and only when the run can
justify the cost: a push to ``main`` or ``next``, a manual dispatch, or a
pull request carrying the ``ci:full-matrix`` label.

.. list-table::
   :header-rows: 1
   :widths: 40 25 35

   * - Trigger
     - Linux
     - macOS and Windows
   * - Pull request
     - 3.10 – 3.14
     - —
   * - Pull request labelled ``ci:full-matrix``
     - 3.10 – 3.14
     - 3.10 and 3.14
   * - Push to ``main`` or ``next``
     - 3.10 – 3.14
     - 3.10 and 3.14

That is five jobs on an ordinary pull request and nine on a broad run.

The reasoning is worth stating, because it is the opposite of the usual
"test everything everywhere" instinct. These are pure-Python projects, so
the interpreter version is where the risk lives and the operating system
mostly is not. Of the platforms, Windows is the one that can actually
diverge — ``cp1252`` as the default encoding, path handling — and until
recently it was not tested at all. macOS differs from Linux in nothing
these libraries touch.

There was also a concrete failure mode. Running five macOS jobs per pull
request sat exactly on GitHub's free-tier limit of five concurrent macOS
jobs for public repositories, so two overlapping runs queued behind each
other until they timed out. Two macOS jobs leave headroom.

Windows is currently ``continue-on-error``: it reports its result without
blocking a merge, until it has a track record. Remove that once it has
one.

To get the broad matrix on a pull request, add the ``ci:full-matrix``
label. The workflow listens for the ``labeled`` event, so the run starts
when the label is applied — no need to push again.

Cutting a release
-----------------

Nothing releases on push. Both kinds of release are cut by dispatching
the ``CI`` workflow from the Actions tab and choosing the branch:

``next``
    Cuts a release candidate, ``X.Y.Z-rc.N``.

``main``
    Cuts the GA release, ``X.Y.Z``.

semantic-release works out the version from the commits, writes it into
``pyproject.toml``, ``pyasn1/__init__.py`` and ``CHANGELOG.md``, commits
that as ``chore(release): X.Y.Z``, tags it, and publishes a GitHub
release. The tag is what reaches PyPI.

To ship a GA: promote ``next`` into ``main`` with a pull request, wait for
it to be green, then dispatch the workflow against ``main``.

Every push — to ``next`` as much as to ``main`` — is a dry run instead.
semantic-release computes the version it *would* cut and tags nothing.
Because its prepare step never runs, nothing is built either, so the
workflow builds that version as ``X.Y.Z.devN`` and keeps it as an artifact
for 14 days. Install that artifact and exercise it before dispatching the
real release.

Releasing by hand rather than on every merge is deliberate. When ``next``
released automatically, it kept cutting release candidates from whatever
base its own history reached, which drifts below ``main`` as soon as a GA
is cut there — see `Keeping next and main in step`_.

Keeping next and main in step
-----------------------------

Promoting ``next`` into ``main`` and then releasing leaves the
``chore(release):`` commit, and the tag on it, on ``main`` only. ``next``
does not contain them, so as far as semantic-release can see from
``next``, the newest release is still the last one that branch cut.

Left alone this drifts. In pysmi it produced ``2.0.0-rc.15`` and
``2.0.0-rc.16`` on PyPI *after* ``2.0.1`` had shipped: release candidates
numbered below a released version, uploaded after it.

So after cutting a GA on ``main``, merge ``main`` back into ``next``. This
is the only direction in which ``main`` should ever be merged into
``next``, and it carries nothing but the release commit.

Commits on ``next`` that are not on ``main`` are the normal state of
things and need no action: that is unreleased work waiting for the next
promotion.

Reaching PyPI
-------------

Publishing is a separate workflow (``publish-to-pypi.yml``) triggered by
the tag that semantic-release pushes. Keeping it separate means a failed
upload can be re-run without re-running the release, and the tag is the
only thing that can cause an upload.

It runs in three stages: verify that the tag matches the version recorded
in ``pyproject.toml``, build the distributions, then upload them.

The upload uses `PyPI Trusted Publishing
<https://docs.pypi.org/trusted-publishers/>`_. No API token exists
anywhere in the repository. PyPI matches four claims from the run's OIDC
token — owner, repository, workflow filename, and environment name — and
mints a credential valid for that run alone. Under Trusted Publishing the
upload also carries `PEP 740 <https://peps.python.org/pep-0740/>`_
attestations by default.

The trusted publisher is registered on the PyPI project's *Publishing*
settings page and must name the workflow file exactly:

==================  ========================
Claim               Value
==================  ========================
Owner               ``pysnmp``
Repository          ``pyasn1``
Workflow name       ``publish-to-pypi.yml``
Environment name    ``release``
==================  ========================

Renaming the workflow file or the environment breaks publishing until the
publisher is re-registered.

Documentation publishing
------------------------

Every release tag publishes its own documentation. ``docs-publish.yml``
builds the docs for the tag and writes them to a directory named for the
version on the ``gh-pages`` branch, then rebuilds the aliases from
whatever directories are present:

``stable``
    The newest final release.

``latest``
    The newest release of any kind, including release candidates.

Because the aliases, the root redirect and ``versions.json`` are rebuilt
from the directory listing on every run, re-running the workflow repairs
the site rather than adding to a broken one.

Troubleshooting
---------------

**A run was cancelled and no step failed.** Look at whether the jobs were
killed part-way through. Runner processes that die mid-suite, with no
assertion failure in the log, are usually out of memory rather than
cancelled. A run whose overall conclusion is ``cancelled`` while
individual jobs report ``failure`` with exit code 143 was terminated from
outside.

**A release did not happen after merging to** ``next``. Merging does not
release; dispatch the workflow. If a dispatch also released nothing, check
the commit subjects — only ``fix``, ``feat``, ``perf`` and breaking
changes produce a release, so a branch of nothing but ``docs`` and
``chore`` commits correctly releases nothing. The ``Build Release`` job
log states which commits it analysed and what it concluded.

**PyPI rejected the upload with 403.** The trusted publisher does not
match. Confirm all four fields on the PyPI publishing settings page
against the table above; the workflow filename is the one most often
wrong.

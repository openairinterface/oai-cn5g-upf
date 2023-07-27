# Contributing to OpenAir-CN #

We want to make contributing to this project as easy and transparent as possible.

Please refer to the steps described on our website: [How to contribute to OAI](https://www.openairinterface.org/?page_id=112)

1. Sign and return a Contributor License Agreement to OAI team.
2. Create an account on [Eurecom GiLab Server](https://gitlab.eurecom.fr/users/sign_up)
   - If your email domain (`@domain.com`) is not whitelisted, please contact us (mailto:contact@openairinterface.org).
   - Eurecom GitLab does NOT accept public email domains.
3. Provide the identifiant of this account to the OAI team (mailto:contact@openairinterface.org) so you have developer rights on this repository.
4. The policies are described in these wiki pages: [OAI Policies](https://gitlab.eurecom.fr/oai/openairinterface5g/wikis/oai-policies-home)
   - You can fork onto another hosting system. But we will **NOT** accept a pull request from a forked repository.
      * This decision was made for the license reasons.
      * The Continuous Integration will reject your pull request.
   - All pull requests SHALL have **`develop`** branch as target branch.

## Synchronizing GIT sub-modules ##

We are using nested GIT submodules. To synchronize them, the 2 most important commands to know are :

1. `git submodule deinit --force .`
2. `git submodule update --init --recursive`

If you have non-tracked files or modified files within git submodules, these commands may not work.

Use the `--verbose` option to see the execution of each command.

If the synchronization fails, you may need to go into the path of the failing git-submodule(s) and clean the workspace from non-tracked/modified files.

## Coding Styles ##

We are using `clang-format` as formatting tool on the C/C++ code.

At the time of writing (Jubeh 20th, 2023), we are using `clang-format` version 12.0.0.

On a Ubuntu20+ server, to install:

```bash
sudo apt-get install -y clang-format-12
sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-12 20
```

How to format:

```bash
$ cd myClonedWorkspace/src
$ clang-format -i theFilesYouWantToFormat
```

## License ##

By contributing to OpenAirInterface, you agree that your contributions will be licensed under the [LICENSE](LICENSE) file in the root directory of this source tree.

## Continuous Integration process ##

<<<<<<< HEAD
1.  You push your modified code with the new branch onto our [official GitHub repository](https://github.com/OPENAIRINTERFACE/oai-upf).
    -  Please make the name of the branch explicit and short.
2.  You create a pull request from the [dedicated web page](https://github.com/OPENAIRINTERFACE/oai-upf/pulls).
=======
1.  You push your modified code with the new branch onto our [official GitLab repository](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf).
    -  Please make the name of the branch explicit and short.
2.  You create a merge request from the [dedicated web page](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf/-/merge_requests).
>>>>>>> 93f5efddafe4c5deff12e1a8d617c21f6feb6977
    -  The `target` (`base` in the web-page) branch **SHALL be `develop`**.
    -  The `source` (`compare` in the web-page) branch is your branch.
3.  Our Continuous Integration (CI) process will be triggered automatically on your proposed modified code and check the validity.
    -  Check build
    -  Check some formatting rules
    -  Run a bunch of tests
4.  If at least one of these steps fails, you will have to push corrections onto your source branch.
    -  The step 3. will be again automatically triggered on this new commit.
    -  Please wait that your run is finished before committing and pushing new modifications on your source branch.
    -  That will allow fairness on the CI usage to other contributors.
4.  When this automated process passes, one of our CI administrators will review your changes or assign a senior contributor
  to do a peer-review.
5.  Once the peer reviewer accepts your modification, one of our CI administrators will accept and merge your merge request
    -  The CI will run again on the new `develop` branch commit.
    -  The source branch WILL be deleted by one of our CI administrators.


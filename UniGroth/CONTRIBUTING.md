# Contributing

Thank you for thinking about helping out with `arkworks-rs/groth16`!

Helping this project can be done in many ways, like talking in the discussions or suggesting code changes. To keep things easy for everyone, we have a simple plan for helping out:

1) Find an issue you want to help with.
2) Talk about it in the discussion for that issue.
3) If you want to start working:
    * Make sure the idea has been accepted by others.
    * Make sure no one else is already working on it. If they are, try to work together!
    * If no one is assigned, leave a comment saying you want to start. This helps us not do the same work twice.
    * Use the standard way: fork the project, make a new branch, and send a "Pull Request" (PR) when you're done.
    * Remember to add a note in the "Pending" part of `CHANGELOG.md`.

For tiny things like fixing a typo, you don't need to ask first. Just send the fix! But for big changes, it's always best to talk about it first so your hard work doesn't get rejected.

## Branch Structure

The main part of the project is in the `master` branch. This is where all the finished fixes go. Other branches are for testing new ideas.

## How to work on a fork

If you are new to this:
1) "Fork" the project on GitHub to make your own copy.
2) Download it to your computer.
3) Add the main project as a "remote" so you can get updates:
```bash
git remote add upstream git@github.com:arkworks-rs/groth16.git
```
4) When you want to fix something, make a new branch with a clear name.
5) Do your work, save it, and send it back to us!

## Updating documentation

We love clear explanations! Don't assume the code is easy to understand. It's very helpful to describe what a block of code does in plain English. If you can, mention what part of the research paper you are following.

## Performance improvements

If you make the code faster, please show us with a test! Sometimes things that seem like they should be faster actually aren't because of how computers work deep down. Always test your speed improvements!
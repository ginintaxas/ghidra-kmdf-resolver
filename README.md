## KMDF function resolver

### Usage  
Like any other pyghidra script you put it in pyghirda_scripts or somewhere similar and then launch it from the code browser. Don't forget to launch ghidra with jython enabled.
### What it does
This python script (as the name suggests) resolves kmdf function names from given offsets
Before:

<img width="563" height="87" alt="image" src="https://github.com/user-attachments/assets/9df958e1-a1b5-4c24-9fad-71d0cd6165f9" />

After:

<img width="668" height="72" alt="image" src="https://github.com/user-attachments/assets/f137a1de-2d7d-4843-9945-ab371a324426" />

### Quick note
Rememeber that these pointers resolve to a stub that calls the actual function because wdf drivers load them dynamically, so the first arg to any function is a pointer to globals.

<img width="504" height="17" alt="image" src="https://github.com/user-attachments/assets/c5cf5d8b-6382-41d9-b6d0-a3b0de8dd336" />

### Future
I am planning to code even more features in to make the life of wdf reverse engineers even simpler.
Also accepting any PRs or features implemented

##general bash commands
| | |
| ------------- |:-------------|
| history | prints out a numbers list of historical commands |
| !654 | executes the command number 654 from history |
| vim *file* | powerful text editor, but takes some learning |
| cat *file* | read out the contents of the file to the terminal |
| less *file* | more powerfull than cat.  it gives you the abililty to search and scroll, among many other things |
| *newcommand* !! | execute your new command followed by the previous command (!!) |
| *newcommand* !$ | execute your new command followed by the last word of your previous command. |



##grep command
The grep command is basically like a filter for anything that comes accross your terminal.  A very common use of grep is to filter a large file or trim down the terminal output to only show things that you care about.

For example, to check if a process is running, you could run the command `ps -u jasonrhaas`.  This shows you all the processes that are running on the username **jasonrhaas**.

An output on my computer looks like this:

	501 33457 ??         0:00.09 com.apple.qtkitserver
	501 33458 ??         0:00.02 com.apple.audio.SandboxHelper
	501 33459 ??         0:00.04 com.apple.audio.ComponentHelper
	501 33471 ??         1:22.23 /Applications/Mou.app/Contents/MacOS/Mou
	501 33486 ??         0:00.35 /System/Library/Frameworks/	QuickLook.framework/Resources/quicklookd.app/Co
	501 33490 ??         0:00.27 com.apple.quicklook.satellite
	501 33498 ??         0:05.33 com.apple.WebKit.WebContent
	501 33505 ??         0:03.29 com.apple.WebKit.WebContent
	501 33541 ??         0:00.04 /System/Library/Frameworks/	CoreServices.framework/Frameworks/Metadata.fram
	0 33049 ttys000    0:00.06 login -pfl jasonrhaas /bin/bash -c exec -la bash /bin/bash


This is only a small portion of the processes that are running.  But lets say this list is huge and I only care about if Mou is running.  Well I could use **grep** to filter this list.  If I run `ps -u jasonrhaas | grep Mou`

The output will look like this

	501 33471 ??         1:45.21 /Applications/Mou.app/Contents/MacOS/M
	501 33565 ttys000    0:00.00 grep Mou

Now it's very easy to tell that Mou is running.

### More on grep
There's lots more you can do with grep.  For example, `grep -v` will give you everything in the sentence minus the word you specific.  If you do `grep -e` you can use regular expressions.

##The Pipe |
The pipe is this symbol `|`.  It is used to direct any output from the terminal to the next command after the pipe.  In the **grep** example, the output from the `ps` command was directed to `grep`, and the output of that showed up on the terminal.

##Input and output redirection
`<` is used to direct something to be an input.

`>` is used to direct something to be an output.
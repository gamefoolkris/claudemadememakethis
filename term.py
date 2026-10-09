import XTerm;

term = XTerm.Socket();
term.start("/bin/zsh", "~/", [["assets/xterm.html", "/"],["assets/js/xterm.js", "/js/xterm.js"],["assets/style/xterm.css", "/style/xterm.css"],["assets/js/addon-fit.js", "/js/addon-fit.js"]], "127.0.0.1", "27361", True);

# pipenv使用

```shell
$ pipenv shell
$ pipenv install 
$ pipenv  
```

# 解决python升级导致pipenv不可用问题。
当Python版本升级后，会出现如下问题：
```
$ pipenv    
dyld: Library not loaded: @executable_path/../.Python
  Referenced from: /usr/local/Cellar/pipenv/2018.11.26_2/libexec/bin/python3.7
  Reason: image not found
[1]    53674 abort      pipenv
```

解决方案:

```shell
$ brew upgrade pipenv
$ pipenv shell
Warning: Your Pipfile requires python_version 3.9, but you are using unknown (/Users/z/.local/share/v/P/bin/python).
  $ pipenv --rm and rebuilding the virtual environment may resolve the issue.
  $ pipenv check will surely fail.
Launching subshell in virtual environment...
 ~/.local/share/virtualenvs/PythonStudy-6xxBBS_s/bin/activate
$ pipenv --rm
$ pipenv check
```
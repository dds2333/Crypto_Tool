# Crypto_Tool
密码学工具（包含 SM2 加解密、SM3、SM4 加解密 以及常用哈希算法），基于 WPF 与 BouncyCastle

代码写得很辣鸡，除了界面，核心代码全都在 MainWindow.xaml.cs 中。

XD

更新：

- 计算文件摘要时，支持 > 2 GB 的文件；并将计算过程改为后台线程，使得主界面在计算大文件的哈希时不至于卡死;

- 修复计算杂凑时多线程 I/O 争用问题

demo：

![demo](https://github.com/dds2333/Crypto_Tool/blob/master/demo.png)

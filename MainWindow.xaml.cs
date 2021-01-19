using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Microsoft.Win32;
using System.IO;
using System.Diagnostics;
using Org.BouncyCastle.Crypto.Digests;
using System.ComponentModel;

namespace Crypto_Tool
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {

        byte[] global_iv = null;
        bool is_fromfile = false;
        Stream Hash_stream = null;
        byte[] hash_res = null;
        public static object locker = new object();

        private readonly BackgroundWorker _BGdWorker_md5 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha1 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha2_224 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha2_256 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha2_384 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha2_512 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha3_224 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha3_256 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha3_384 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sha3_512 = new BackgroundWorker();
        private readonly BackgroundWorker _BGdWorker_sm3 = new BackgroundWorker();

        #region SM2

        //国密标准256位曲线参数
        BigInteger SM2_ECC_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
        BigInteger SM2_ECC_A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
        BigInteger SM2_ECC_B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
        BigInteger SM2_ECC_N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
        BigInteger SM2_ECC_H = BigInteger.One;
        BigInteger SM2_ECC_GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
        BigInteger SM2_ECC_GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);


        public MainWindow()
        {
            InitializeComponent();

            _BGdWorker_md5.DoWork += new DoWorkEventHandler(Md5_dowork);
            _BGdWorker_md5.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Md5_work_completed);
            //_BGdWorker_md5.ProgressChanged += new ProgressChangedEventHandler(Md5_work_ProgressChanged);

            _BGdWorker_sha1.DoWork += new DoWorkEventHandler(Sha1_dowork);
            _BGdWorker_sha1.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha1_work_completed);

            _BGdWorker_sha2_224.DoWork += new DoWorkEventHandler(Sha2_224_dowork);
            _BGdWorker_sha2_224.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha2_224_work_completed);

            _BGdWorker_sha2_256.DoWork += new DoWorkEventHandler(Sha2_256_dowork);
            _BGdWorker_sha2_256.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha2_256_work_completed);

            _BGdWorker_sha2_384.DoWork += new DoWorkEventHandler(Sha2_384_dowork);
            _BGdWorker_sha2_384.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha2_384_work_completed);

            _BGdWorker_sha2_512.DoWork += new DoWorkEventHandler(Sha2_512_dowork);
            _BGdWorker_sha2_512.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha2_512_work_completed);

            _BGdWorker_sha3_224.DoWork += new DoWorkEventHandler(Sha3_224_dowork);
            _BGdWorker_sha3_224.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha3_224_work_completed);

            _BGdWorker_sha3_256.DoWork += new DoWorkEventHandler(Sha3_256_dowork);
            _BGdWorker_sha3_256.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha3_256_work_completed);

            _BGdWorker_sha3_384.DoWork += new DoWorkEventHandler(Sha3_384_dowork);
            _BGdWorker_sha3_384.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha3_384_work_completed);

            _BGdWorker_sha3_512.DoWork += new DoWorkEventHandler(Sha3_512_dowork);
            _BGdWorker_sha3_512.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sha3_512_work_completed);

            _BGdWorker_sm3.DoWork += new DoWorkEventHandler(Sm3_dowork);
            _BGdWorker_sm3.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Sm3_work_completed);

            //计算杂凑时，默认选中的项
            cb_filesize.IsChecked = true;
            cb_mdtime.IsChecked = true;
            cb_toUpper.IsChecked = true;
            cb_md5.IsChecked = true;
            cb_sha1.IsChecked = true;
            cb_sha2_256.IsChecked = true;
            //cb_sha2_512.IsChecked = true;
            cb_sm3.IsChecked = true;
        }

        /// <summary>
        /// 选择文件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_selfile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog op = new OpenFileDialog();
            op.Title = "选择待加密的文件";
            op.DefaultExt = ".txt";
            op.Filter = "All files|*.*";
            if (op.ShowDialog() == true)
            {
                tb_filepath.Clear();
                tb_filepath.Text = op.FileName;
                tb_input.Clear();
            }
            op.FilterIndex = 0;
            op.CheckFileExists = true;
            op.CheckPathExists = true;
        }

        private void tb_filepath_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }

        private void tb_filepath_PreviewDrop(object sender, DragEventArgs e)
        {
            string[] data = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (data == null || data.Length < 1)
            {
                return;
            }
            else
            {
                tb_filepath.Clear();//清空
                tb_filepath.Text = data[0];
                tb_input.Clear();
            }
        }

        /// <summary>
        /// 生成公私钥对
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_genkey_Click(object sender, RoutedEventArgs e)
        {
            ECCurve curve = new FpCurve(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
            ECPoint g = curve.CreatePoint(SM2_ECC_GX, SM2_ECC_GY);
            ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
            keyPairGenerator.Init(aKeyGenParams);
            AsymmetricCipherKeyPair aKp = keyPairGenerator.GenerateKeyPair();
            ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.Public;
            ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.Private;

            BigInteger privateKey = aPriv.D;
            ECPoint publicKey = aPub.Q;
            byte[] pubkey = Hex.Encode(publicKey.GetEncoded());
            string temp_pubkey = Encoding.UTF8.GetString(pubkey).ToUpper();
            tb_pubinfo.Text = temp_pubkey;
            MessageBox.Show("下一步：保存公钥", "提示");
            SaveFileDialog sfd = new SaveFileDialog();
            sfd.Title = "保存公钥";
            sfd.Filter = "All files|*.pub";
            if (sfd.ShowDialog() == true)
            {
                FileStream fs = new FileStream(sfd.FileName, FileMode.Create, FileAccess.Write);
                fs.Write(pubkey, 0, pubkey.Length);
                fs.Close();
                MessageBox.Show("已成功保存公钥至" + sfd.FileName, "提示");
            }
            else
            {
                MessageBox.Show("请保存公钥到文件！！", "提示");

            }
            string temp_prikey = Encoding.UTF8.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper();
            tb_priInfo.Text = temp_prikey;
            byte[] prikey = Encoding.UTF8.GetBytes(temp_prikey);
            MessageBox.Show("下一步：保存私钥", "提示");
            SaveFileDialog sfd1 = new SaveFileDialog();
            sfd1.Title = "保存私钥";
            sfd1.Filter = "All files|*.pri";
            if (sfd1.ShowDialog() == true)
            {
                FileStream fs = new FileStream(sfd1.FileName, FileMode.Create, FileAccess.Write);
                fs.Write(prikey, 0, prikey.Length);
                fs.Close();
                MessageBox.Show("已成功保存私钥至" + sfd1.FileName, "提示");
            }
            else
            {
                MessageBox.Show("请保存私钥到文件！！", "提示");
                return;
            }
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_en_Click(object sender, RoutedEventArgs e)
        {
            if (tb_filepath.Text == string.Empty && tb_input.Text == string.Empty)
            {
                MessageBox.Show("请选择待加密的文件或者输入数据！！", "提示");
                return;
            }
            else
            {
                byte[] bytedata, tmpdata = null;
                if (tb_input.Text == string.Empty && tb_filepath.Text != string.Empty)
                {
                    //tmpdata = FiletoByte(tb_filepath.Text);
                    tmpdata = File.ReadAllBytes(tb_filepath.Text);
                }
                else if (tb_input.Text != string.Empty && tb_filepath.Text == string.Empty)
                {
                    tmpdata = Encoding.UTF8.GetBytes(tb_input.Text);
                }
                bytedata = tmpdata;
                Stopwatch watch = new Stopwatch();
                if (tb_pubinfo.Text == string.Empty)
                {
                    MessageBox.Show("请生成密钥对或导入公钥！！", "提示");
                    return;
                }
                string pubkey = tb_pubinfo.Text;
                watch.Start();
                string ciphertext = Encrypt(Hex.Decode(pubkey), bytedata);
                watch.Stop();
                tb_en.Clear();
                tb_en.Text = "加密耗时：" + watch.ElapsedMilliseconds.ToString() + "ms(毫秒)";
                byte[] cipher_bytedata = Encoding.UTF8.GetBytes(ciphertext);
                tb_res.Clear();
                tb_res.AppendText(ciphertext);

                if (tb_input.Text == string.Empty && tb_filepath.Text != string.Empty)
                {
                    string extension = System.IO.Path.GetExtension(tb_filepath.Text);
                    SaveFileDialog sfd = new SaveFileDialog();
                    sfd.Title = "保存加密文件";
                    sfd.Filter = "All files|*" + extension;
                    if (sfd.ShowDialog() == true)
                    {
                        FileStream fs = new FileStream(sfd.FileName, FileMode.Create, FileAccess.Write);
                        fs.Write(cipher_bytedata, 0, cipher_bytedata.Length);
                        tb_en.AppendText(" 加密文件路径：" + sfd.FileName);
                        fs.Close();
                        MessageBox.Show("已成功加密文件！！", "提示");
                    }
                    else
                    {
                        MessageBox.Show("请保存密文文件！！", "提示");
                        return;
                    }
                }
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_de_Click(object sender, RoutedEventArgs e)
        {
            string extension = null;
            string encrypt_bytedata = null;
            if (tb_input.Text == string.Empty)
            {
                OpenFileDialog op = new OpenFileDialog();
                op.Title = "选择待解密的文件";
                op.DefaultExt = ".txt";
                op.Filter = "All files|*.*";
                if (op.ShowDialog() == true)
                {
                    string temp_path = op.FileName;
                    extension = System.IO.Path.GetExtension(temp_path);
                    //MessageBox.Show(temp_path);
                    //byte[] temp_encrypt_bytedata = FiletoByte(temp_path);
                    byte[] temp_encrypt_bytedata = File.ReadAllBytes(temp_path);
                    encrypt_bytedata = Encoding.Default.GetString(temp_encrypt_bytedata);
                }
                else
                {
                    MessageBox.Show("请选择待解密的文件", "提示");
                    return;
                }
            }
            else
            {
                byte[] tmp = Encoding.UTF8.GetBytes(tb_input.Text);
                if (tmp.Length <= 97)
                {
                    MessageBox.Show("请检查密文是否正确", "错误");
                    return;
                }
                else
                {
                    encrypt_bytedata = Encoding.UTF8.GetString(tmp);
                }
            }

            Stopwatch watch = new Stopwatch();
            if (tb_priInfo.Text == string.Empty)
            {
                MessageBox.Show("请生成密钥对或导入私钥！！", "提示");
                return;
            }
            string prikey = tb_priInfo.Text.ToUpper();
            watch.Start();
            byte[] plain_bytedata = Decrypt(Hex.Decode(prikey), Hex.Decode(encrypt_bytedata));
            watch.Stop();
            tb_de.Clear();
            tb_de.Text = "解密耗时：" + watch.ElapsedMilliseconds.ToString() + "ms(毫秒)";
            if (tb_input.Text == string.Empty)
            {
                SaveFileDialog sfd = new SaveFileDialog();
                sfd.Title = "保存解密文件";
                sfd.Filter = "All files|*" + extension;
                if (sfd.ShowDialog() == true)
                {
                    FileStream fs = new FileStream(sfd.FileName, FileMode.Create, FileAccess.Write);
                    fs.Write(plain_bytedata, 0, plain_bytedata.Length);
                    tb_de.AppendText("解密文件路径：" + sfd.FileName);
                    fs.Close();
                    MessageBox.Show("已成功解密文件！！", "提示");
                }
                else
                {
                    MessageBox.Show("请保存解密文件", "提示");
                    return;
                }
            }
            else
            {
                tb_res.Clear();
                tb_res.AppendText(Encoding.UTF8.GetString(plain_bytedata));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_inpub_Click(object sender, RoutedEventArgs e)
        {
            tb_pubinfo.Clear();//清空
            OpenFileDialog op = new OpenFileDialog();
            op.Title = "导入公钥";
            op.DefaultExt = ".pub";
            op.Filter = "All files|*.pub";
            if (op.ShowDialog() == true)
            {
                string temp_path = op.FileName;
                //byte[] temp_pubkey = FiletoByte(temp_path);
                byte[] temp_pubkey = File.ReadAllBytes(temp_path);
                string pubkey = Encoding.Default.GetString(temp_pubkey).ToUpper();
                tb_pubinfo.Text = pubkey;
            }
            else
            {
                MessageBox.Show("请选择存储公钥的文件", "提示");
                return;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_inpri_Click(object sender, RoutedEventArgs e)
        {
            tb_priInfo.Clear();//清空
            OpenFileDialog op = new OpenFileDialog();
            op.Title = "导入私钥";
            op.DefaultExt = ".pri";
            op.Filter = "All files|*.pri";
            if (op.ShowDialog() == true)
            {
                string temp_path = op.FileName;
                //byte[] temp_prikey = FiletoByte(temp_path);
                byte[] temp_prikey = File.ReadAllBytes(temp_path);
                string prikey = Encoding.Default.GetString(temp_prikey).ToUpper();
                tb_priInfo.Text = prikey;
            }
            else
            {
                MessageBox.Show("请选择存储私钥的文件", "提示");
                return;
            }
        }

        #region 自定义函数
        /// <summary>
        /// 加密函数
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public string Encrypt(byte[] publicKey, byte[] data)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }
            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);
            ECCurve curve = new FpCurve(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
            ECPoint g = curve.CreatePoint(SM2_ECC_GX, SM2_ECC_GY);
            ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);
            ECPoint userkey = curve.DecodePoint(publicKey);
            ECPublicKeyParameters aPub = new ECPublicKeyParameters(userkey, domainParams);

            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.Init(true, new ParametersWithRandom(aPub));
            byte[] enc = sm2Engine.ProcessBlock(source, 0, source.Length);
            return Encoding.Default.GetString(Hex.Encode(enc));
        }

        /// <summary>
        /// 解密函数
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] privateKey, byte[] encryptedData)
        {
            if (null == privateKey || privateKey.Length == 0)
            {
                return null;
            }
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            byte[] enc = new byte[encryptedData.Length];
            Array.Copy(encryptedData, 0, enc, 0, encryptedData.Length);
            BigInteger userD = new BigInteger(1, privateKey);
            ECCurve curve = new FpCurve(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
            ECPoint g = curve.CreatePoint(SM2_ECC_GX, SM2_ECC_GY);
            ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);
            ECPrivateKeyParameters aPriv = new ECPrivateKeyParameters(userD, domainParams);

            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.Init(false, aPriv);
            byte[] dec = sm2Engine.ProcessBlock(enc, 0, enc.Length);
            return dec;
        }

        /// <summary>
        /// 文件转换成字节数组
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        //private byte[] FiletoByte(string path)
        //{
        //    FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        //    try
        //    {
        //        byte[] databytes = new byte[fs.Length];
        //        fs.Read(databytes, 0, (int)fs.Length);
        //        return databytes;
        //    }
        //    catch (Exception)
        //    {
        //        return null;
        //    }
        //    finally
        //    {
        //        if (fs != null)
        //        {
        //            fs.Close();
        //        }
        //    }
        //}
        #endregion

        #endregion

        #region SM4

        //选择文件
        private void bt_selfile_sm4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog op = new OpenFileDialog();
            op.Title = "选择待加密的文件";
            op.DefaultExt = ".txt";
            op.Filter = "All files|*.*";
            if (op.ShowDialog() == true)
            {
                tb_filepath_sm4.Clear();
                tb_filepath_sm4.Text = op.FileName;
                tb_input_sm4.Clear();
            }
            op.FilterIndex = 0;
            op.CheckFileExists = true;
            op.CheckPathExists = true;
        }

        private void tb_sy_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }

        private void tb_filepath_sm4_PreviewDrop(object sender, DragEventArgs e)
        {
            string[] data = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (data == null || data.Length < 1)
            {
                return;
            }
            else
            {
                tb_filepath_sm4.Clear();//清空
                tb_filepath_sm4.Text = data[0];
                tb_input_sm4.Clear();
            }
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_en_sm4_Click(object sender, RoutedEventArgs e)
        {
            if (tb_filepath_sm4.Text == string.Empty && tb_input_sm4.Text == string.Empty)
            {
                MessageBox.Show("请选择待加密的文件或者输入数据！！", "提示");
                return;
            }
            else
            {
                byte[] bytedata, tmpdata = null;
                if (tb_input_sm4.Text == string.Empty && tb_filepath_sm4.Text != string.Empty)
                {
                    tmpdata = File.ReadAllBytes(tb_filepath_sm4.Text);
                }
                else if (tb_input_sm4.Text != string.Empty && tb_filepath_sm4.Text == string.Empty)
                {
                    tmpdata = Encoding.UTF8.GetBytes(tb_input_sm4.Text);
                }
                bytedata = tmpdata;

                if (tb_key.Text == string.Empty)
                {
                    MessageBox.Show("请输入密钥！！", "提示");
                    return;
                }

                tb_res_sm4.Clear();
                tb_eninfo_sm4.Clear();

                string tmp_key = tb_key.Text;
                byte[] key_tmp = Encoding.Default.GetBytes(tmp_key);
                byte[] digest;
                SM3Digest md = new SM3Digest();
                md.BlockUpdate(key_tmp, 0, key_tmp.Length);
                digest = new byte[md.GetDigestSize()];
                md.DoFinal(digest, 0);
                string hex = Encoding.Default.GetString(Hex.Encode(digest));
                string key_temp = hex.Substring(0, 32);
                byte[] keybytes = Hex.Decode(key_temp);

                byte[] cipher, hex_cipher = null, iv = null;

                //Stopwatch watch = new Stopwatch();
                //watch.Reset();

                if (rb_ecb.IsChecked == true)//ECB模式
                {

                    //watch.Start();
                    //DateTime beforDT = DateTime.Now;
                    cipher = sm4_encrypt(bytedata, keybytes, "ECB", null);
                    //DateTime afterDT = DateTime.Now;
                    //watch.Stop();
                    //time = watch.ElapsedMilliseconds;
                    //TimeSpan ts = afterDT.Subtract(beforDT);
                    //time = ts.TotalMilliseconds;
                    hex_cipher = Hex.Encode(cipher);
                    //string str_cipher = Encoding.UTF8.GetString(hex_cipher);
                }
                else if (rb_cbc.IsChecked == true)//CBC模式
                {
                    iv = geniv();
                    global_iv = iv;
                    tb_iv.Text = Encoding.UTF8.GetString(global_iv);
                    cipher = sm4_encrypt(bytedata, keybytes, "CBC", iv);
                    hex_cipher = Hex.Encode(cipher);
                    //string str_cipher = Encoding.UTF8.GetString(hex_cipher);
                }
                else if (rb_cfb.IsChecked == true)//CFB模式
                {
                    iv = geniv();
                    global_iv = iv;
                    tb_iv.Text = Encoding.UTF8.GetString(global_iv);
                    cipher = sm4_encrypt(bytedata, keybytes, "CFB", iv);
                    hex_cipher = Hex.Encode(cipher);
                    //string str_cipher = Encoding.UTF8.GetString(hex_cipher);
                }
                else if (rb_ofb.IsChecked == true)//OFB模式
                {
                    iv = geniv();
                    global_iv = iv;
                    tb_iv.Text = Encoding.UTF8.GetString(global_iv);
                    cipher = sm4_encrypt(bytedata, keybytes, "OFB", iv);
                    hex_cipher = Hex.Encode(cipher);
                    //string str_cipher = Encoding.UTF8.GetString(hex_cipher);
                }
                else if (rb_ctr.IsChecked == true)//CTR模式
                {
                    iv = geniv();
                    global_iv = iv;
                    tb_iv.Text = Encoding.UTF8.GetString(global_iv);
                    cipher = sm4_encrypt(bytedata, keybytes, "CTR", iv);
                    hex_cipher = Hex.Encode(cipher);
                    //string str_cipher = Encoding.UTF8.GetString(hex_cipher);
                }
                else
                {
                    MessageBox.Show("请选择加密模式！！", "提示");
                    return;
                }

                if (hex_cipher != null)
                {
                    string str_cipher = Encoding.UTF8.GetString(hex_cipher);

                    if (global_iv != null)
                    {
                        string str_iv = Encoding.UTF8.GetString(global_iv);
                        byte[] hex_iv_cipher = Encoding.UTF8.GetBytes(str_iv + str_cipher);
                        hex_cipher = hex_iv_cipher;
                    }

                    tb_res.Clear();
                    tb_res_sm4.AppendText(str_cipher);

                    if (tb_input_sm4.Text == string.Empty && tb_filepath_sm4.Text != string.Empty)
                    {

                        string extension = System.IO.Path.GetExtension(tb_filepath_sm4.Text);
                        SaveFileDialog sfd = new SaveFileDialog();
                        sfd.Title = "保存加密文件";
                        sfd.Filter = "All files|*" + extension;
                        if (sfd.ShowDialog() == true)
                        {
                            FileStream fs = new FileStream(sfd.FileName, FileMode.Create, FileAccess.Write);
                            fs.Write(hex_cipher, 0, hex_cipher.Length);
                            tb_eninfo_sm4.AppendText(" 加密文件路径：" + sfd.FileName);
                            fs.Close();
                            MessageBox.Show("已成功加密文件！！", "提示");
                        }
                        else
                        {
                            MessageBox.Show("请保存密文文件！！", "提示");
                            return;
                        }

                    }
                    else if (tb_input_sm4.Text != string.Empty && tb_filepath_sm4.Text == string.Empty)
                    {
                        tb_eninfo_sm4.Text = "加密完成，详见运算结果";
                    }
                }
                else
                {
                    return;
                }
            }
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_de_sm4_Click(object sender, RoutedEventArgs e)
        {
            if (tb_filepath_sm4.Text == string.Empty && tb_input_sm4.Text == string.Empty)
            {
                MessageBox.Show("请选择待解密的文件或者输入数据！！", "提示");
                return;
            }
            else
            {
                byte[] bytedata = null, bytedata_de = null, datafrominput = null;

                if (tb_input_sm4.Text == string.Empty && tb_filepath_sm4.Text != string.Empty)
                {

                    bytedata = File.ReadAllBytes(tb_filepath_sm4.Text);
                    try
                    {
                        bytedata_de = Hex.Decode(bytedata);
                    }
                    catch (Exception)
                    {
                        MessageBox.Show("密文格式不正确！！", "提示");
                        return;
                    }
                    is_fromfile = true;
                }
                else if (tb_input_sm4.Text != string.Empty && tb_filepath_sm4.Text == string.Empty)
                {
                    datafrominput = Encoding.UTF8.GetBytes(tb_input_sm4.Text);
                    try
                    {
                        bytedata_de = Hex.Decode(datafrominput);
                    }
                    catch (Exception)
                    {
                        MessageBox.Show("密文格式不正确！！", "提示");
                        return;
                    }
                    is_fromfile = false;
                }

                if (tb_key.Text == string.Empty)
                {
                    MessageBox.Show("请输入密钥！！", "提示");
                    return;
                }

                tb_res_sm4.Clear();
                tb_deinfo_sm4.Clear();

                string tmp_key = tb_key.Text;
                byte[] key_tmp = Encoding.Default.GetBytes(tmp_key);
                byte[] digest;
                SM3Digest md = new SM3Digest();
                md.BlockUpdate(key_tmp, 0, key_tmp.Length);
                digest = new byte[md.GetDigestSize()];
                md.DoFinal(digest, 0);
                string hex = Encoding.UTF8.GetString(Hex.Encode(digest));
                string key_temp = hex.Substring(0, 32);
                byte[] keybytes = Hex.Decode(key_temp);

                byte[] plain = null;
                byte[] iv = new byte[16];
                byte[] file_bytedata = null;

                if (rb_ecb.IsChecked == true)
                {
                    plain = sm4_decrypt(bytedata_de, keybytes, "ECB", null);
                }
                else if (rb_cbc.IsChecked == true)
                {
                    if (is_fromfile == false)
                    {
                        iv = Encoding.UTF8.GetBytes(tb_iv.Text);
                        plain = sm4_decrypt(bytedata_de, keybytes, "CBC", iv);
                    }
                    else
                    {
                        Array.Copy(bytedata, iv, 16);
                        file_bytedata = new byte[bytedata.Length - 16];
                        Array.Copy(bytedata, 16, file_bytedata, 0, (bytedata.Length - 16));//获取除去初始向量后的密文数据
                        plain = sm4_decrypt(Hex.Decode(file_bytedata), keybytes, "CBC", iv);
                    }
                }
                else if (rb_cfb.IsChecked == true)
                {
                    if (is_fromfile == false)
                    {
                        iv = Encoding.UTF8.GetBytes(tb_iv.Text);
                        plain = sm4_decrypt(bytedata_de, keybytes, "CFB", iv);
                    }
                    else
                    {
                        Array.Copy(bytedata, iv, 16);
                        file_bytedata = new byte[bytedata.Length - 16];
                        Array.Copy(bytedata, 16, file_bytedata, 0, (bytedata.Length - 16));
                        plain = sm4_decrypt(Hex.Decode(file_bytedata), keybytes, "CFB", iv);
                    }
                }
                else if (rb_ofb.IsChecked == true)
                {
                    if (is_fromfile == false)
                    {
                        iv = Encoding.UTF8.GetBytes(tb_iv.Text);
                        plain = sm4_decrypt(bytedata_de, keybytes, "OFB", iv);
                    }
                    else
                    {
                        Array.Copy(bytedata, iv, 16);
                        file_bytedata = new byte[bytedata.Length - 16];
                        Array.Copy(bytedata, 16, file_bytedata, 0, (bytedata.Length - 16));
                        plain = sm4_decrypt(Hex.Decode(file_bytedata), keybytes, "OFB", iv);
                    }
                }
                else if (rb_ctr.IsChecked == true)
                {
                    if (is_fromfile == false)
                    {
                        iv = Encoding.UTF8.GetBytes(tb_iv.Text);
                        plain = sm4_decrypt(bytedata_de, keybytes, "CTR", iv);
                    }
                    else
                    {
                        Array.Copy(bytedata, iv, 16);
                        file_bytedata = new byte[bytedata.Length - 16];
                        Array.Copy(bytedata, 16, file_bytedata, 0, (bytedata.Length - 16));
                        plain = sm4_decrypt(Hex.Decode(file_bytedata), keybytes, "CTR", iv);
                    }
                }
                else
                {
                    MessageBox.Show("请选择解密模式！！", "提示");
                    return;
                }

                if (plain != null)
                {
                    string str_plain = Encoding.UTF8.GetString(plain);
                    tb_res.Clear();
                    tb_res_sm4.AppendText(str_plain);

                    if (is_fromfile == true)//输入为文件时
                    {

                        string extension = System.IO.Path.GetExtension(tb_filepath_sm4.Text);
                        SaveFileDialog sfd = new SaveFileDialog();
                        sfd.Title = "保存解密文件";
                        sfd.Filter = "All files|*" + extension;
                        if (sfd.ShowDialog() == true)
                        {
                            FileStream fs = new FileStream(sfd.FileName, FileMode.Create, FileAccess.Write);
                            fs.Write(plain, 0, plain.Length);
                            tb_deinfo_sm4.AppendText(" 解密文件路径：" + sfd.FileName);
                            fs.Close();
                            MessageBox.Show("已成功解密文件！！", "提示");
                        }
                        else
                        {
                            MessageBox.Show("请保存文件！！", "提示");
                            return;
                        }

                    }
                    else
                    {
                        tb_deinfo_sm4.Text = "解密完成，详见运算结果";
                    }
                }
                else
                {
                    MessageBox.Show("解密失败！请检查密钥与模式是否正确！！", "提示");
                    return;
                }
            }
        }

        /// <summary>
        /// 加密函数
        /// </summary>
        /// <param name="plain"></param>
        /// <param name="user_key"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        private byte[] sm4_encrypt(byte[] plain, byte[] keyBytes, string mode, byte[] iv)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            if (mode.Equals("ECB"))
            {
                IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/ECB/PKCS7Padding");
                inCipher.Init(true, key);
                byte[] cipher = inCipher.DoFinal(plain);
                return cipher;
            }
            else if (mode.Equals("CBC") && iv != null)
            {
                ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
                inCipher.Init(true, keyParamWithIv);
                byte[] cipher = inCipher.DoFinal(plain);
                return cipher;
            }
            else if (mode.Equals("CFB") && iv != null)
            {
                ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CFB/PKCS7Padding");
                inCipher.Init(true, keyParamWithIv);
                byte[] cipher = inCipher.DoFinal(plain);
                return cipher;
            }
            else if (mode.Equals("OFB") && iv != null)
            {
                ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/OFB/PKCS7Padding");
                inCipher.Init(true, keyParamWithIv);
                byte[] cipher = inCipher.DoFinal(plain);
                return cipher;
            }
            else if (mode.Equals("CTR") && iv != null)
            {
                ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CTR/PKCS7Padding");
                inCipher.Init(true, keyParamWithIv);
                byte[] cipher = inCipher.DoFinal(plain);
                return cipher;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// 解密函数
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="keyBytes"></param>
        /// <param name="mode"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        private byte[] sm4_decrypt(byte[] cipher, byte[] keyBytes, string mode, byte[] iv)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            if (mode.Equals("ECB"))
            {
                try
                {
                    IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/ECB/PKCS7Padding");
                    inCipher.Init(false, key);
                    byte[] plain = inCipher.DoFinal(cipher);
                    return plain;
                }
                catch (Exception)
                {
                    return null;
                }

            }
            else if (mode.Equals("CBC") && iv != null)
            {
                try
                {
                    ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                    IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
                    inCipher.Init(false, keyParamWithIv);
                    byte[] plain = inCipher.DoFinal(cipher);
                    return plain;
                }
                catch (Exception)
                {
                    return null;
                }

            }
            else if (mode.Equals("CFB") && iv != null)
            {
                try
                {
                    ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                    IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CFB/PKCS7Padding");
                    inCipher.Init(false, keyParamWithIv);
                    byte[] plain = inCipher.DoFinal(cipher);
                    return plain;
                }
                catch (Exception)
                {
                    return null;
                }

            }
            else if (mode.Equals("OFB") && iv != null)
            {
                try
                {
                    ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                    IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/OFB/PKCS7Padding");
                    inCipher.Init(false, keyParamWithIv);
                    byte[] plain = inCipher.DoFinal(cipher);
                    return plain;
                }
                catch (Exception)
                {
                    return null;
                }

            }
            else if (mode.Equals("CTR") && iv != null)
            {
                try
                {
                    ParametersWithIV keyParamWithIv = new ParametersWithIV(key, iv);
                    IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CTR/PKCS7Padding");
                    inCipher.Init(false, keyParamWithIv);
                    byte[] plain = inCipher.DoFinal(cipher);
                    return plain;
                }
                catch (Exception)
                {
                    return null;
                }

            }
            else
            {
                return null;
            }
        }


        /// <summary>
        /// 生成iv
        /// </summary>
        /// <returns></returns>
        private byte[] geniv()
        {
            SecureRandom random = new SecureRandom();
            byte[] rd = new byte[8];
            random.NextBytes(rd);
            string rd_str = Encoding.Default.GetString(Hex.Encode(rd));
            byte[] iv = Encoding.UTF8.GetBytes(rd_str);
            return iv;
        }

        #endregion

        #region 杂凑

        /// <summary>
        /// 选择文件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_hash_Click(object sender, RoutedEventArgs e)
        {

            OpenFileDialog op = new OpenFileDialog();
            op.Title = "选择待杂凑的文件";
            op.DefaultExt = ".txt";
            op.Filter = "All files|*.*";
            if (op.ShowDialog() == true)
            {
                tb_filepath_hash.Clear();
                tb_filepath_hash.Text = op.FileName;
                tb_input_hash.Clear();
            }
            op.FilterIndex = 0;
            op.CheckFileExists = true;
            op.CheckPathExists = true;
        }

        private void tb_filepath_hash_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }

        private void tb_filepath_hash_PreviewDrop(object sender, DragEventArgs e)
        {
            string[] data = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (data == null || data.Length < 1)
            {
                return;
            }
            else
            {
                tb_filepath_hash.Clear();//清空
                tb_filepath_hash.Text = data[0];
                tb_input_hash.Clear();
            }
        }

        private void Md5_dowork(object sender, DoWorkEventArgs e)
        {          
            hash_res = Md5_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Md5_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "MD5：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "MD5：" + e.Result.ToString());
                }
            }
        }

        private void Sha1_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha1_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha1_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA1：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA1：" + e.Result.ToString());
                }
            }
        }

        private void Sha2_224_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha2_224_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha2_224_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-224：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-224：" + e.Result.ToString());
                }
            }
        }

        private void Sha2_256_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha2_256_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha2_256_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-256：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-256：" + e.Result.ToString());
                }
            }
        }

        private void Sha2_384_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha2_384_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha2_384_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-384：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-384：" + e.Result.ToString());
                }
            }
        }

        private void Sha2_512_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha2_512_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha2_512_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-512：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA2-512：" + e.Result.ToString());
                }
            }
        }

        private void Sha3_224_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha3_224_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha3_224_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-224：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-224：" + e.Result.ToString());
                }
            }
        }

        private void Sha3_256_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha3_256_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha3_256_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-256：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-256：" + e.Result.ToString());
                }
            }
        }

        private void Sha3_384_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha3_384_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha3_384_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-384：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-384：" + e.Result.ToString());
                }
            }
        }

        private void Sha3_512_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sha3_512_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sha3_512_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-512：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SHA3-512：" + e.Result.ToString());
                }
            }
        }

        private void Sm3_dowork(object sender, DoWorkEventArgs e)
        {
            hash_res = Sm3_stream(Hash_stream);
            string res = Encoding.UTF8.GetString(Hex.Encode(hash_res));
            e.Result = res;
        }

        private void Sm3_work_completed(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            else
            {
                if (cb_toUpper.IsChecked == true)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SM3：" + e.Result.ToString().ToUpper());
                }
                else
                {
                    rtb_res_hash.AppendText(Environment.NewLine + "SM3：" + e.Result.ToString());
                }
            }
        }


        /// <summary>
        /// 计算
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_calcula_hash_Click(object sender, RoutedEventArgs e)
        {
            if (tb_filepath_hash.Text == string.Empty && tb_input_hash.Text == string.Empty)
            {
                MessageBox.Show("请选择待杂凑的文件或者输入数据！！！", "提示");
                return;
            }
            else
            {
                if (Hash_stream != null)
                {
                    Hash_stream.Close();
                }

                if (rtb_res_hash.Document.Blocks.Count > 1)
                {
                    rtb_res_hash.AppendText(Environment.NewLine + Environment.NewLine);
                }
                byte[] bytedata = null, cal_res = null;

                if (tb_input_hash.Text == string.Empty && tb_filepath_hash.Text != string.Empty)
                {
                    //bytedata = File.ReadAllBytes(tb_filepath_hash.Text);
                    Stream stream = File.OpenRead(tb_filepath_hash.Text);
                    Hash_stream = stream;

                    rtb_res_hash.AppendText("文件路径：" + tb_filepath_hash.Text);
                    rtb_res_hash.AppendText(Environment.NewLine + "文件大小：" + stream.Length + " 字节");
                    FileInfo fi = new FileInfo(tb_filepath_hash.Text);
                    rtb_res_hash.AppendText(Environment.NewLine + "修改时间：" + fi.LastWriteTime.ToString());                 

                    if (cb_md5.IsChecked == true)
                    {
                        _BGdWorker_md5.RunWorkerAsync();                     
                    }
                    if (cb_sha1.IsChecked == true)
                    {
                        _BGdWorker_sha1.RunWorkerAsync();                      
                    }
                    if (cb_sha2_224.IsChecked == true)
                    {
                        _BGdWorker_sha2_224.RunWorkerAsync();
                    }
                    if (cb_sha2_256.IsChecked == true)
                    {
                        _BGdWorker_sha2_256.RunWorkerAsync();
                    }
                    if (cb_sha2_384.IsChecked == true)
                    {
                        _BGdWorker_sha2_384.RunWorkerAsync();
                    }
                    if (cb_sha2_512.IsChecked == true)
                    {
                        _BGdWorker_sha2_512.RunWorkerAsync();
                    }
                    if (cb_sm3.IsChecked == true)
                    {
                        _BGdWorker_sm3.RunWorkerAsync();
                    }
                    if (cb_sha3_224.IsChecked == true)
                    {
                        _BGdWorker_sha3_224.RunWorkerAsync();
                    }
                    if (cb_sha3_256.IsChecked == true)
                    {
                        _BGdWorker_sha3_256.RunWorkerAsync();
                    }
                    if (cb_sha3_384.IsChecked == true)
                    {
                        _BGdWorker_sha3_384.RunWorkerAsync();
                    }
                    if (cb_sha3_512.IsChecked == true)
                    {
                        _BGdWorker_sha3_512.RunWorkerAsync();
                    }

                    if (cb_md5.IsChecked == false && cb_sha1.IsChecked == false && cb_sha2_224.IsChecked == false && cb_sha2_256.IsChecked == false
                        && cb_sha2_384.IsChecked == false && cb_sha2_512.IsChecked == false && cb_sm3.IsChecked == false && cb_sha3_224.IsChecked == false
                        && cb_sha3_256.IsChecked == false && cb_sha3_384.IsChecked == false && cb_sha3_512.IsChecked == false)
                    {
                        MessageBox.Show("请选择至少一种杂凑算法！！！", "提示");
                        return;
                    }
                }
                else if (tb_input_hash.Text != string.Empty && tb_filepath_hash.Text == string.Empty)
                {
                    bytedata = Encoding.UTF8.GetBytes(tb_input_hash.Text);
                    rtb_res_hash.AppendText("待杂凑原文：" + tb_input_hash.Text);

                    if (cb_md5.IsChecked == true)
                    {
                        cal_res = Md5(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "MD5：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "MD5：" + res);
                        }
                    }
                    if (cb_sha1.IsChecked == true)
                    {
                        cal_res = Sha1(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA1：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA1：" + res);
                        }
                    }
                    if (cb_sha2_224.IsChecked == true)
                    {
                        cal_res = Sha2_224(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-224：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-224：" + res);
                        }
                    }
                    if (cb_sha2_256.IsChecked == true)
                    {
                        cal_res = Sha2_256(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-256：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-256：" + res);
                        }
                    }
                    if (cb_sha2_384.IsChecked == true)
                    {
                        cal_res = Sha2_384(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-384：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-384：" + res);
                        }
                    }
                    if (cb_sha2_512.IsChecked == true)
                    {
                        cal_res = Sha2_512(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-512：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA2-512：" + res);
                        }
                    }
                    if (cb_sm3.IsChecked == true)
                    {
                        cal_res = Sm3(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SM3：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SM3：" + res);
                        }
                    }
                    if (cb_sha3_224.IsChecked == true)
                    {
                        cal_res = Sha3_224(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText("SHA3-224：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-224：" + res);
                        }
                    }
                    if (cb_sha3_256.IsChecked == true)
                    {
                        cal_res = Sha3_256(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-256：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-256：" + res);
                        }
                    }
                    if (cb_sha3_384.IsChecked == true)
                    {
                        cal_res = Sha3_384(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-384：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-384：" + res);
                        }
                    }
                    if (cb_sha3_512.IsChecked == true)
                    {
                        cal_res = Sha3_512(bytedata);
                        string res = Encoding.UTF8.GetString(Hex.Encode(cal_res));
                        if (cb_toUpper.IsChecked == true)
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-512：" + res.ToUpper());
                        }
                        else
                        {
                            rtb_res_hash.AppendText(Environment.NewLine + "SHA3-512：" + res);
                        }
                    }

                    if (cb_md5.IsChecked == false && cb_sha1.IsChecked == false && cb_sha2_224.IsChecked == false && cb_sha2_256.IsChecked == false
                       && cb_sha2_384.IsChecked == false && cb_sha2_512.IsChecked == false && cb_sm3.IsChecked == false && cb_sha3_224.IsChecked == false
                       && cb_sha3_256.IsChecked == false && cb_sha3_384.IsChecked == false && cb_sha3_512.IsChecked == false)
                    {
                        MessageBox.Show("请选择至少一种杂凑算法！！！", "提示");
                        return;
                    }
                }
            }
        }

        /// <summary>
        /// 清空
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_clear_hash_Click(object sender, RoutedEventArgs e)
        {
            rtb_res_hash.Document.Blocks.Clear();
            tb_filepath_hash.Clear();
            if (Hash_stream != null)
            {
                Hash_stream.Close();
            }
        }

        /// <summary>
        /// 复制结果
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_copy_hash_Click(object sender, RoutedEventArgs e)
        {
            if (rtb_res_hash.Document.Blocks.Count > 1)
            {
                TextRange textRange = new TextRange(
                    rtb_res_hash.Document.ContentStart,
                    rtb_res_hash.Document.ContentEnd
                    );
                Clipboard.SetText(textRange.Text);
            }
            else
            {
                MessageBox.Show("请先计算杂凑！！！", "提示");
                return;
            }
        }

        /// <summary>
        /// 保存结果至文件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void bt_save_hash_Click(object sender, RoutedEventArgs e)
        {
            if (rtb_res_hash.Document.Blocks.Count > 1)
            {

                TextRange textRange = new TextRange(
                   rtb_res_hash.Document.ContentStart,
                   rtb_res_hash.Document.ContentEnd
                   );
                byte[] res = Encoding.UTF8.GetBytes(textRange.Text);
                SaveFileDialog sfd = new SaveFileDialog();
                sfd.Title = "保存文件";
                sfd.Filter = "All files|*" + ".txt";
                if (sfd.ShowDialog() == true)
                {
                    FileStream fs = new FileStream(sfd.FileName, FileMode.Create, FileAccess.Write);
                    fs.Write(res, 0, res.Length);
                    fs.Close();
                    MessageBox.Show("已成功保存文件！", "提示");
                }
                else
                {
                    MessageBox.Show("请保存文件！！", "提示");
                    return;
                }
            }
            else
            {
                MessageBox.Show("请先计算杂凑！！！", "提示");
                return;
            }
        }

        /// <summary>
        /// MD5
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Md5(byte[] data)
        {
            MD5Digest Md5_digest = new MD5Digest();
            Md5_digest.BlockUpdate(data, 0, data.Length);
            byte[] md5_value = new byte[Md5_digest.GetDigestSize()];
            Md5_digest.DoFinal(md5_value, 0);
            return md5_value;
        }
        //使用 Stream 计算杂凑可突破 2 GB 的文件限制
        private byte[] Md5_stream(Stream stream)
        {
            MD5Digest Md5_digest = new MD5Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            //加锁，防止出现线程 I/O 争用
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Md5_digest.BlockUpdate(buffer, 0, bytesRead);
                }
            }
            byte[] md5_value = new byte[Md5_digest.GetDigestSize()];
            Md5_digest.DoFinal(md5_value, 0);
            return md5_value;
        }

        /// <summary>
        /// sha1
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha1(byte[] data)
        {
            Sha1Digest sha_1 = new Sha1Digest();
            sha_1.BlockUpdate(data, 0, data.Length);
            byte[] sha1_value = new byte[sha_1.GetDigestSize()];
            sha_1.DoFinal(sha1_value, 0);
            return sha1_value;
        }
        private byte[] Sha1_stream(Stream stream)
        {
            Sha1Digest sha_1 = new Sha1Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha_1.BlockUpdate(buffer, 0, bytesRead);
                }
            }           
            byte[] sha1_value = new byte[sha_1.GetDigestSize()];
            sha_1.DoFinal(sha1_value, 0);
            return sha1_value;
        }

        /// <summary>
        /// sha2_224
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha2_224(byte[] data)
        {
            Sha224Digest sha2_224 = new Sha224Digest();
            sha2_224.BlockUpdate(data, 0, data.Length);
            byte[] sha2_224_value = new byte[sha2_224.GetDigestSize()];
            sha2_224.DoFinal(sha2_224_value, 0);
            return sha2_224_value;
        }
        private byte[] Sha2_224_stream(Stream stream)
        {
            Sha224Digest sha2_224 = new Sha224Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha2_224.BlockUpdate(buffer, 0, bytesRead);
                }
            }         
            byte[] sha2_224_value = new byte[sha2_224.GetDigestSize()];
            sha2_224.DoFinal(sha2_224_value, 0);
            return sha2_224_value;
        }

        /// <summary>
        /// sha2_256
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha2_256(byte[] data)
        {
            Sha256Digest sha2_256 = new Sha256Digest();
            sha2_256.BlockUpdate(data, 0, data.Length);
            byte[] sha2_256_value = new byte[sha2_256.GetDigestSize()];
            sha2_256.DoFinal(sha2_256_value, 0);
            return sha2_256_value;
        }
        private byte[] Sha2_256_stream(Stream stream)
        {
            Sha256Digest sha2_256 = new Sha256Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha2_256.BlockUpdate(buffer, 0, bytesRead);
                }
            }        
            byte[] sha2_256_value = new byte[sha2_256.GetDigestSize()];
            sha2_256.DoFinal(sha2_256_value, 0);
            return sha2_256_value;
        }

        /// <summary>
        /// sha2_384
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha2_384(byte[] data)
        {
            Sha384Digest sha2_384 = new Sha384Digest();
            sha2_384.BlockUpdate(data, 0, data.Length);
            byte[] sha2_384_value = new byte[sha2_384.GetDigestSize()];
            sha2_384.DoFinal(sha2_384_value, 0);
            return sha2_384_value;
        }
        private byte[] Sha2_384_stream(Stream stream)
        {
            Sha384Digest sha2_384 = new Sha384Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha2_384.BlockUpdate(buffer, 0, bytesRead);
                }
            }      
            byte[] sha2_384_value = new byte[sha2_384.GetDigestSize()];
            sha2_384.DoFinal(sha2_384_value, 0);
            return sha2_384_value;
        }

        /// <summary>
        /// sha2_512
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha2_512(byte[] data)
        {
            Sha512Digest sha2_512 = new Sha512Digest();
            sha2_512.BlockUpdate(data, 0, data.Length);
            byte[] sha2_512_value = new byte[sha2_512.GetDigestSize()];
            sha2_512.DoFinal(sha2_512_value, 0);
            return sha2_512_value;
        }
        private byte[] Sha2_512_stream(Stream stream)
        {
            Sha512Digest sha2_512 = new Sha512Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha2_512.BlockUpdate(buffer, 0, bytesRead);
                }
            }           
            byte[] sha2_512_value = new byte[sha2_512.GetDigestSize()];
            sha2_512.DoFinal(sha2_512_value, 0);
            return sha2_512_value;
        }

        /// <summary>
        /// sm3
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sm3(byte[] data)
        {
            SM3Digest sm3 = new SM3Digest();
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] sm3_value = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(sm3_value, 0);
            return sm3_value;
        }
        private byte[] Sm3_stream(Stream stream)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sm3.BlockUpdate(buffer, 0, bytesRead);
                }
            }           
            byte[] sm3_value = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(sm3_value, 0);
            return sm3_value;
        }

        /// <summary>
        /// sha3_224
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha3_224(byte[] data)
        {
            Sha3Digest sha3_224 = new Sha3Digest(224);
            sha3_224.BlockUpdate(data, 0, data.Length);
            byte[] sha3_224_value = new byte[sha3_224.GetDigestSize()];
            sha3_224.DoFinal(sha3_224_value, 0);
            return sha3_224_value;
        }
        private byte[] Sha3_224_stream(Stream stream)
        {
            Sha3Digest sha3_224 = new Sha3Digest(224);
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha3_224.BlockUpdate(buffer, 0, bytesRead);
                }
            }          
            byte[] sha3_224_value = new byte[sha3_224.GetDigestSize()];
            sha3_224.DoFinal(sha3_224_value, 0);
            return sha3_224_value;
        }

        /// <summary>
        /// sha3_256
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha3_256(byte[] data)
        {
            Sha3Digest sha3_256 = new Sha3Digest(256);
            sha3_256.BlockUpdate(data, 0, data.Length);
            byte[] sha3_256_value = new byte[sha3_256.GetDigestSize()];
            sha3_256.DoFinal(sha3_256_value, 0);
            return sha3_256_value;
        }
        private byte[] Sha3_256_stream(Stream stream)
        {
            Sha3Digest sha3_256 = new Sha3Digest(256);
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha3_256.BlockUpdate(buffer, 0, bytesRead);
                }
            }          
            byte[] sha3_256_value = new byte[sha3_256.GetDigestSize()];
            sha3_256.DoFinal(sha3_256_value, 0);
            return sha3_256_value;
        }

        /// <summary>
        /// sha3_384
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha3_384(byte[] data)
        {
            Sha3Digest sha3_384 = new Sha3Digest(384);
            sha3_384.BlockUpdate(data, 0, data.Length);
            byte[] sha3_384_value = new byte[sha3_384.GetDigestSize()];
            sha3_384.DoFinal(sha3_384_value, 0);
            return sha3_384_value;
        }
        private byte[] Sha3_384_stream(Stream stream)
        {
            Sha3Digest sha3_384 = new Sha3Digest(384);
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha3_384.BlockUpdate(buffer, 0, bytesRead);
                }
            }         
            byte[] sha3_384_value = new byte[sha3_384.GetDigestSize()];
            sha3_384.DoFinal(sha3_384_value, 0);
            return sha3_384_value;
        }

        /// <summary>
        /// sah3_512
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha3_512(byte[] data)
        {
            Sha3Digest sha3_512 = new Sha3Digest(512);
            sha3_512.BlockUpdate(data, 0, data.Length);
            byte[] sha3_512_value = new byte[sha3_512.GetDigestSize()];
            sha3_512.DoFinal(sha3_512_value, 0);
            return sha3_512_value;
        }
        private byte[] Sha3_512_stream(Stream stream)
        {
            Sha3Digest sha3_512 = new Sha3Digest(512);
            byte[] buffer = new byte[4092];
            int bytesRead;
            lock (locker)
            {
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha3_512.BlockUpdate(buffer, 0, bytesRead);
                }
            }         
            byte[] sha3_512_value = new byte[sha3_512.GetDigestSize()];
            sha3_512.DoFinal(sha3_512_value, 0);
            return sha3_512_value;
        }

        #endregion
        private void Window_Closed(object sender, EventArgs e)
        {
            if (Hash_stream != null)
            {
                Hash_stream.Close();
            }        
        }
    }
}

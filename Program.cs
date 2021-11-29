namespace Aes_Bin_Tam
{
    class Program
    {
        static void Main(string[] args)
        {
            int option = 1;
            while (true)
            {
                if (option >= 1 && option <= 6)
                {
                    AesHelper.showMenuOption();
                }
                try
                {
                    option = Int32.Parse(Console.ReadLine());
                    //Console.ReadLine();
                }
                catch (Exception e)
                {
                    option = -1;
                    //sc.nextLine();
                }
                switch (option)
                {
                    case 1:
                        Encryption.ECBEncryptionWithKey();
                        break;
                    case 2:
                        Encryption.CBCEncryptionWithKey();
                        break;
                    case 3:
                        Encryption.ECBEncryptionWithRandomKey();
                        break;
                    case 4:
                        Encryption.CBCEncryptionWithRandomKey();
                        break;
                    case 5:
                        Encryption.diffBit();
                        break;
                    case 6:
                        break;
                    default:
                        Console.WriteLine("Vui lòng nhập đúng lựa chọn .");
                        Console.Write("Chọn lại: ");
                        break;
                }
                Console.WriteLine();
                if (option == 6)
                {
                    Console.WriteLine("BYE!");
                    break;
                }
            }
        }
    }
}
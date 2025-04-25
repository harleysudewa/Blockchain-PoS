# Blockchain Proof-of-Stake (PoS) Simulation

Aplikasi ini merupakan simulasi blockchain dengan mekanisme konsensus **Proof of Stake (PoS)**. Aplikasi ini mensimulasikan proses pemilihan validator untuk membuat block transaksi baru berdasarkan jumlah stake yang dimiliki, tanpa proses mining—melainkan melalui pemilihan acak berbobot (weighted random selection). Aplikasi ini menyediakan dua interface yang dapat digunakan, yaitu GUI (Graphical User Interface) dan CLI (Command Line Interface). Berikut adalah fitur-fitur yang tersedia pada masing-masing interface.

## 🖥️ Fitur GUI

1.	**Tab Dashboard:**
- Tab ini memiliki dua bagian: **Blockchain Stats** dan **Activity Log.**
	- **Blockchain Stats** menampilkan informasi statistik terkini dari jaringan blockchain, seperti jumlah total block, jumlah transaksi yang masih tertunda, dan total validator aktif.
	- **Activity Log** merekam dan menampilkan log aktivitas yang terjadi di dalam sistem, seperti pembuatan transaksi, validasi block, dan penambahan validator. Selain itu, pada tab ini juga terdapat button untuk me-refresh dashboard dan meng-export jaringan blockchain ke file JSON.

2.	**Tab Transactions:**
- Tab ini memiliki dua bagian: **Create Transactions** dan **Pending Transactions.**
	- **Create Transactions** memungkinkan pengguna untuk membuat transaksi baru dengan menentukan pengirim, penerima, dan jumlah.
	- Transaksi yang dibuat kemudian ditandatangani secara digital oleh pengirim menggunakan private key-nya dan akan masuk ke dalam **Pending Transactions**, menunggu proses validasi dari validator aktif. Setelah transaksi divalidasi dan dimasukkan ke dalam block, transaksi tersebut akan dihapus dari daftar pending dan resmi tercatat dalam blockchain. Selain itu, juga terdapat button untuk me-refresh transaksi.
    
3.	**Tab Validators:**
- Tab ini memiliki dua bagian: **Add Validator** dan **Active Validators.**
	- **Add Validator** digunakan untuk menambahkan validator baru ke dalam jaringan blockchain dengan jumlah stake tertentu.
    - **Active Validators** menampilkan semua validator yang ada pada jaringan blockchain tersebut. Informasi yang ditampilkan adalah alamat validator dan jumlah stake yang mereka miliki. Selain itu, juga terdapat button untuk me-refresh validator.

4.	**Tab Blocks:**
- Tab ini memiliki tiga bagian: **Block Details**, **Blockchain**, dan **Selected Block Details.**
    - **Blockchain** berfungsi untuk menampilkan semua block yang ada dalam jaringan blockchain tersebut. Informasi yang ditampilkan adalah block index dan validator block tersebut.
    - **Block Details** berfungsi untuk memasukkan block yang ingin dicari informasi detailnya. Inputnya adalah block index.
	- **Selected Block Details** menampilkan informasi detail berdasarkan block index yang telah dimasukkan pada bagian **Block Details**. Informasi detail yang ditampilkan adalah index, hash, timestamp, pengirim, penerima, jumlah, ID transaksi, digital signature, validator yang memvalidasi, dan hash dari block sebelumnya.

5.	**Tab Visualizations:**
- Tab ini memiliki dua bagian: **Stake Distribution** dan **Blockchain Visualization.**
	- **Stake Distribution** akan menampilkan distribusi stake yang dimiliki oleh semua validator yang ada dalam jaringan blockchain tersebut. Dalam sistem PoS ini, validator untuk membuat blok baru tidak dipilih secara acak murni, tetapi berdasarkan probabilitas yang sebanding dengan jumlah stake yang mereka miliki. Semakin besar stake seorang validator, semakin besar peluangnya untuk dipilih membentuk blok. Distribusi stake divisualisasikan dalam bentuk pie chart.
	- **Blockchain Visualization** akan menampilkan jaringan blockchain menggunakan grafik dengan node-node yang mewakili dan block Visualisasi ini membantu pengguna memahami topologi dan alur pembentukan block dalam blockchain secara interaktif. Selain itu, juga terdapat button untuk me-refresh visualisasi.

## 💻 Fitur CLI

1. **Menu 1 (Create a new transaction):** 
- Digunakan untuk membuat transaksi baru di jaringan.
	- Pengguna akan diminta memasukkan pengirim, penerima, dan jumlahnya.
	- Transaksi kemudian ditandatangani secara digital oleh pengirim menggunakan private key-nya dan dimasukkan ke daftar transaksi pending.
	- Setelah divalidasi oleh validator, transaksi akan dimasukkan ke dalam block dan tercatat permanen di jaringan blockchain.

2. **Menu 2 (Display blockchain):**
- Menampilkan keseluruhan isi jaringan blockchain dalam format JSON. Setiap block yang sudah terbentuk akan ditampilkan secara lengkap, seperti index, hash, timestamp, pengirim, penerima, jumlah, ID transaksi, digital signature, validator yang memvalidasi, dan hash dari block sebelumnya.

3. **Menu 3 (Check validator info):**
- Menampilkan informasi detail mengenai validator tertentu berdasarkan alamat. Informasi meliputi jumlah stake yang dimiliki validator.

4. **Menu 4 (Check block info):**
- Menampilkan informasi detail dari blok tertentu berdasarkan block index. Digunakan untuk melihat informasi detail dari block tertentu, seperti index, hash, timestamp, pengirim, penerima, jumlah, ID transaksi, digital signature, validator yang memvalidasi, dan hash dari block sebelumnya.

5. **Menu 5 (Add a new validator):**
- Menambahkan validator baru ke jaringan dengan alamat dan jumlah stake.

6. **Menu 6 (Save blockchain to file):**
- Meng-export jaringan blockchain saat ini ke dalam file JSON. Nama file dapat ditentukan oleh pengguna (default: blockchain.json).

7. **Menu 7 (Exit):**
- Memberhentikan program Blockchain PoS Simulation.

## Instalasi

1. Clone repositori ini:

    ```bash
    git clone https://github.com/harleysudewa/Blockchain-PoS.git
    cd Blockchain-PoS
    ```

2. Install dependensi:

    ```bash
    pip install -r requirements.txt
    ```

    Atau secara manual:

    ```bash
    pip install cryptography matplotlib networkx
    ```

## Menjalankan Aplikasi

```bash
python blockchain-pos.py
```


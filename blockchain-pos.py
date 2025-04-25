import json
import random
import time
import hashlib
import base64
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx

class Transaction:
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = time.time()
        self.signature = signature
        self.transaction_id = self.calculate_hash()
    
    def calculate_hash(self):
        transaction_string = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        return hashlib.sha256(transaction_string.encode()).hexdigest()
    
    def sign_transaction(self, private_key):
        transaction_string = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        signature = private_key.sign(
            transaction_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.signature = base64.b64encode(signature).decode('utf-8')
        return self.signature
    
    def verify_signature(self, public_key):
        if not self.signature:
            return False
        
        transaction_string = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        signature = base64.b64decode(self.signature.encode('utf-8'))
        
        try:
            public_key.verify(
                signature,
                transaction_string.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'transaction_id': self.transaction_id,
            'signature': self.signature
        }

class Block:
    def __init__(self, index, previous_hash, timestamp=None, transactions=None, validator=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp if timestamp else time.time()
        self.transactions = transactions if transactions else []
        self.validator = validator
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.transactions}{self.validator}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def add_transaction(self, transaction):
        self.transactions.append(transaction)
    
    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'validator': self.validator,
            'hash': self.hash
        }

class Validator:
    def __init__(self, address, stake, private_key=None, public_key=None):
        self.address = address
        self.stake = stake
        self.private_key = private_key if private_key else rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = public_key if public_key else self.private_key.public_key()
    
    def to_dict(self):
        return {
            'address': self.address,
            'stake': self.stake
        }

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.validators = {}  # address -> Validator
        self.mining = False
        self.mining_thread = None
        self.callback = None
    
    def create_genesis_block(self):
        return Block(0, "0", time.time(), [], "Genesis")
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_validator(self, address, stake):
        validator = Validator(address, stake)
        self.validators[address] = validator
        return validator
    
    def select_validator(self):
        # select a validator randomly, weighted by stake
        total_stake = sum(validator.stake for validator in self.validators.values())
        if total_stake == 0:
            return None
        
        selection_point = random.uniform(0, total_stake)
        current_sum = 0
        
        for validator in self.validators.values():
            current_sum += validator.stake
            if current_sum >= selection_point:
                return validator
        
        return None
    
    def create_new_block(self, validator):
        # create a new block with current pending transactions
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            previous_hash=latest_block.hash,
            transactions=self.pending_transactions,
            validator=validator.address
        )
        
        self.pending_transactions = []
        self.chain.append(new_block)
        return new_block
    
    def add_transaction(self, transaction):
        # add a transaction to pending transactions
        self.pending_transactions.append(transaction)
        return self.get_latest_block().index + 1
    
    def is_chain_valid(self):
        # validate the blockchain integrity
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def start_mining(self, interval=5):
        # start the validator selection and block creation process
        if self.mining:
            return
        
        self.mining = True
        self.mining_thread = threading.Thread(target=self._mining_loop, args=(interval,))
        self.mining_thread.daemon = True
        self.mining_thread.start()
    
    def stop_mining(self):
        # stop the mining process
        self.mining = False
        if self.mining_thread:
            self.mining_thread.join()
            self.mining_thread = None
    
    def _mining_loop(self, interval):
        # mining process running in a separate thread
        while self.mining:
            time.sleep(interval)
            
            if not self.pending_transactions:
                continue
            
            validator = self.select_validator()
            if validator:
                new_block = self.create_new_block(validator)
                if self.callback:
                    self.callback(f"Block #{new_block.index} created by validator {validator.address}")
    
    def to_json(self):
        # export blockchain to JSON
        return json.dumps({
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': [tx.to_dict() for tx in self.pending_transactions],
            'validators': {addr: val.to_dict() for addr, val in self.validators.items()}
        }, indent=4)
    
    def save_to_file(self, filename='blockchain.json'):
        with open(filename, 'w') as file:
            file.write(self.to_json())
        return filename

class BlockchainCLI:
    def __init__(self):
        self.blockchain = Blockchain()
        self.user_keys = {}  # address -> (private_key, public_key)
    
    def create_user(self, address, initial_stake=0):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        self.user_keys[address] = (private_key, public_key)
        
        if initial_stake > 0:
            self.blockchain.add_validator(address, initial_stake)
        
        return address
    
    def create_transaction(self, sender, recipient, amount):
        if sender not in self.user_keys:
            print(f"Error: Sender {sender} does not exist")
            return None
        
        private_key, _ = self.user_keys[sender]
        transaction = Transaction(sender, recipient, amount)
        transaction.sign_transaction(private_key)
        self.blockchain.add_transaction(transaction)
        return transaction
    
    def get_block_info(self, block_index):
        if block_index < 0 or block_index >= len(self.blockchain.chain):
            return "Block not found"
        
        block = self.blockchain.chain[block_index]
        return json.dumps(block.to_dict(), indent=4)
    
    def get_validator_info(self, address):
        if address not in self.blockchain.validators:
            return "Validator not found"
        
        validator = self.blockchain.validators[address]
        return json.dumps(validator.to_dict(), indent=4)
    
    def display_blockchain(self):
        return self.blockchain.to_json()
    
    def run(self):
        # run the CLI interface
        print("Welcome to Proof-of-Stake Blockchain Simulator")
        print("=============================================")
        
        # add some default validators
        self.create_user("Iwan", 100)
        self.create_user("Handy", 200)
        self.create_user("Petrus", 150)
        
        self.blockchain.callback = print
        self.blockchain.start_mining(interval=5)
        
        while True:
            print("\nSelect an option:")
            print("1. Create a new transaction")
            print("2. Display blockchain")
            print("3. Check validator info")
            print("4. Check block info")
            print("5. Add a new validator")
            print("6. Save blockchain to file")
            print("7. Exit")
            
            choice = input("Enter your choice (1-7): ")
            
            if choice == "1":
                sender = input("Enter sender address: ")
                recipient = input("Enter recipient address: ")
                amount = float(input("Enter amount: "))
                tx = self.create_transaction(sender, recipient, amount)
                if tx:
                    print(f"Transaction created with ID: {tx.transaction_id}")
                    print("Waiting for transaction block to be created and validated...")

                    while True:
                        found = any(tx.transaction_id in [t.transaction_id for t in block.transactions] for block in self.blockchain.chain)
                        if found:
                            print(f"Transaction with ID: {tx.transaction_id} has been created and validated.")
                            break
                        time.sleep(1)
            
            elif choice == "2":
                print(self.display_blockchain())
            
            elif choice == "3":
                address = input("Enter validator address: ")
                print(self.get_validator_info(address))
            
            elif choice == "4":
                block_index = int(input("Enter block index: "))
                print(self.get_block_info(block_index))
            
            elif choice == "5":
                address = input("Enter new validator address: ")
                stake = float(input("Enter stake amount: "))
                self.create_user(address, stake)
                print(f"Validator {address} added with stake {stake}")
            
            elif choice == "6":
                filename = input("Enter filename (default: blockchain.json): ") or "blockchain.json"
                self.blockchain.save_to_file(filename)
                print(f"Blockchain saved to {filename}")
            
            elif choice == "7":
                self.blockchain.stop_mining()
                print("Exiting blockchain simulator...")
                break
            
            else:
                print("Invalid choice. Please try again.")

class BlockchainGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Blockchain PoS Simulator")
        self.master.geometry("660x660")  # GUI Size
        
        self.blockchain_cli = BlockchainCLI()
        self.setup_ui()
        
        self.blockchain_cli.blockchain.callback = self.update_log
        self.blockchain_cli.blockchain.start_mining(interval=5)
    
    def setup_ui(self):
        # create tabs
        self.tab_control = ttk.Notebook(self.master)
        
        # GUI tabs
        self.tab_dashboard = ttk.Frame(self.tab_control)
        self.tab_transactions = ttk.Frame(self.tab_control)
        self.tab_validators = ttk.Frame(self.tab_control)
        self.tab_blocks = ttk.Frame(self.tab_control)
        self.tab_visualizations = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.tab_dashboard, text='Dashboard')
        self.tab_control.add(self.tab_transactions, text='Transactions')
        self.tab_control.add(self.tab_validators, text='Validators')
        self.tab_control.add(self.tab_blocks, text='Blocks')
        self.tab_control.add(self.tab_visualizations, text='Visualizations')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Dashboard tab
        self.setup_dashboard_tab()
        
        # Transactions tab
        self.setup_transactions_tab()
        
        # Validators tab
        self.setup_validators_tab()
        
        # Blocks tab
        self.setup_blocks_tab()
        
        # Visualizations tab
        self.setup_visualizations_tab()
        
        # Add default validators
        self.blockchain_cli.create_user("Iwan", 100.0)
        self.blockchain_cli.create_user("Handy", 200.0)
        self.blockchain_cli.create_user("Petrus", 150.0)
        self.update_validators_list()
    
    def setup_dashboard_tab(self):
        self.tab_dashboard.columnconfigure(0, weight=1)
        self.tab_dashboard.rowconfigure(1, weight=1)
    
        stats_frame = ttk.LabelFrame(self.tab_dashboard, text="Blockchain Stats")
        stats_frame.grid(row=0, column=0, padx=10, pady=10, sticky="")
    
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
    
        ttk.Label(stats_frame, text="Total Blocks:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.lbl_total_blocks = ttk.Label(stats_frame, text="1")
        self.lbl_total_blocks.grid(row=0, column=1, padx=5, pady=5, sticky="w")
    
        ttk.Label(stats_frame, text="Pending Transactions:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.lbl_pending_tx = ttk.Label(stats_frame, text="0")
        self.lbl_pending_tx.grid(row=1, column=1, padx=5, pady=5, sticky="w")
    
        ttk.Label(stats_frame, text="Active Validators:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.lbl_validators = ttk.Label(stats_frame, text="3")
        self.lbl_validators.grid(row=2, column=1, padx=5, pady=5, sticky="w")
    
        log_frame = ttk.LabelFrame(self.tab_dashboard, text="Activity Log")
        log_frame.grid(row=1, column=0, padx=10, pady=(10, 5), sticky="n")
    
        self.log_text = scrolledtext.ScrolledText(log_frame, width=60, height=15)
        self.log_text.grid(row=0, column=0, padx=5, pady=5)
    
        btn_frame = ttk.Frame(log_frame)
        btn_frame.grid(row=1, column=0, padx=5, pady=5)
    
        ttk.Button(btn_frame, text="Export Blockchain", command=self.export_blockchain).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Refresh Dashboard", command=self.update_dashboard).grid(row=0, column=1, padx=5, pady=5)
    
    def setup_transactions_tab(self):
        tx_create_frame = ttk.LabelFrame(self.tab_transactions, text="Create Transaction")
        tx_create_frame.grid(row=0, column=0, padx=10, pady=10, sticky="")
        
        ttk.Label(tx_create_frame, text="From:").grid(row=0, column=0, padx=5, pady=5)
        self.cmb_tx_sender = ttk.Combobox(tx_create_frame, width=15)
        self.cmb_tx_sender.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(tx_create_frame, text="To:").grid(row=1, column=0, padx=5, pady=5)
        self.cmb_tx_recipient = ttk.Combobox(tx_create_frame, width=15)
        self.cmb_tx_recipient.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(tx_create_frame, text="Amount:").grid(row=2, column=0, padx=5, pady=5)
        self.entry_tx_amount = ttk.Entry(tx_create_frame, width=15)
        self.entry_tx_amount.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Button(tx_create_frame, text="Create Transaction", command=self.create_transaction).grid(row=3, column=0, columnspan=2, padx=5, pady=10)
        
        tx_list_frame = ttk.LabelFrame(self.tab_transactions, text="Pending Transactions")
        tx_list_frame.grid(row=1, column=0, padx=10, pady=10, sticky="n")
        
        self.tx_listbox = tk.Listbox(tx_list_frame, width=50, height=10)
        self.tx_listbox.grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(tx_list_frame, text="Refresh Transactions", command=self.update_tx_list).grid(row=1, column=0, padx=5, pady=5)
        
        self.tab_transactions.columnconfigure(0, weight=1)
        self.tab_transactions.rowconfigure(1, weight=1)
    
    def setup_validators_tab(self):
        validator_add_frame = ttk.LabelFrame(self.tab_validators, text="Add Validator")
        validator_add_frame.grid(row=0, column=0, padx=10, pady=10, sticky="")
        
        ttk.Label(validator_add_frame, text="Address:").grid(row=0, column=0, padx=5, pady=5)
        self.entry_validator_addr = ttk.Entry(validator_add_frame, width=20)
        self.entry_validator_addr.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(validator_add_frame, text="Stake:").grid(row=1, column=0, padx=5, pady=5)
        self.entry_validator_stake = ttk.Entry(validator_add_frame, width=20)
        self.entry_validator_stake.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(validator_add_frame, text="Add Validator", command=self.add_validator).grid(row=2, column=0, columnspan=2, padx=5, pady=10)
        
        validator_list_frame = ttk.LabelFrame(self.tab_validators, text="Active Validators")
        validator_list_frame.grid(row=1, column=0, padx=10, pady=10, sticky="n")
        
        self.validators_listbox = tk.Listbox(validator_list_frame, width=30, height=10)
        self.validators_listbox.grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(validator_list_frame, text="Refresh Validators", command=self.update_validators_list).grid(row=1, column=0, padx=5, pady=5)
        
        self.tab_validators.columnconfigure(0, weight=1)
        self.tab_validators.rowconfigure(1, weight=1)
    
    def setup_blocks_tab(self):
        block_info_frame = ttk.LabelFrame(self.tab_blocks, text="Block Details")
        block_info_frame.grid(row=0, column=0, padx=10, pady=10, sticky="")
        
        ttk.Label(block_info_frame, text="Block Index:").grid(row=0, column=0, padx=5, pady=5)
        self.entry_block_index = ttk.Entry(block_info_frame, width=10)
        self.entry_block_index.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(block_info_frame, text="Get Block Info", command=self.get_block_info).grid(row=0, column=2, padx=5, pady=5)
        
        block_list_frame = ttk.LabelFrame(self.tab_blocks, text="Blockchain")
        block_list_frame.grid(row=1, column=0, padx=10, pady=10, sticky="n")
        
        self.blocks_listbox = tk.Listbox(block_list_frame, width=50, height=10)
        self.blocks_listbox.grid(row=0, column=0, padx=5, pady=5)
        
        ttk.Button(block_list_frame, text="Refresh Blocks", command=self.update_blocks_list).grid(row=1, column=0, padx=5, pady=5)
        
        block_details_frame = ttk.LabelFrame(self.tab_blocks, text="Selected Block Details")
        block_details_frame.grid(row=2, column=0, padx=10, pady=10, sticky="n")
        
        self.block_details_text = scrolledtext.ScrolledText(block_details_frame, width=63, height=10)
        self.block_details_text.grid(row=0, column=0, padx=5, pady=5)
        
        self.tab_blocks.columnconfigure(0, weight=1)
        self.tab_blocks.rowconfigure(1, weight=1)
        self.tab_blocks.rowconfigure(2, weight=15)
    
    def setup_visualizations_tab(self):
        viz_frame_top = ttk.LabelFrame(self.tab_visualizations, text="Stake Distribution")
        viz_frame_top.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        viz_frame_bottom = ttk.LabelFrame(self.tab_visualizations, text="Blockchain Visualization")
        viz_frame_bottom.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.fig_pie = plt.Figure(figsize=(8, 2), dpi=100)
        self.ax_pie = self.fig_pie.add_subplot(111)
        self.canvas_pie = FigureCanvasTkAgg(self.fig_pie, viz_frame_top)
        self.canvas_pie.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
        self.fig_network = plt.Figure(figsize=(8, 2), dpi=100)
        self.ax_network = self.fig_network.add_subplot(111)
        self.canvas_network = FigureCanvasTkAgg(self.fig_network, viz_frame_bottom)
        self.canvas_network.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        refresh_button = ttk.Button(self.tab_visualizations, text="Refresh Visualizations", command=self.update_visualizations)
        refresh_button.pack(pady=10)
        
        self.update_visualizations()
    
    def update_visualizations(self):
        self.update_stake_pie_chart()
        self.update_blockchain_network()
    
    def update_stake_pie_chart(self):
        self.ax_pie.clear()
        validators = self.blockchain_cli.blockchain.validators
    
        if not validators:
            self.ax_pie.text(0.5, 0.5, "No validators yet!", ha='center', va='center')
            self.canvas_pie.draw()
            return
    
        labels = list(validators.keys())
        sizes = [validator.stake for validator in validators.values()]
        
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0', '#ffb3e6', '#ff6666', '#99ccff']
        
        self.ax_pie.pie(sizes, labels=labels, autopct='%1.1f%%', 
                        shadow=False, startangle=90, colors=colors)
        self.ax_pie.set_title('Stake Distribution Among Validators')
        self.ax_pie.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        
        self.canvas_pie.draw()
    
    def update_blockchain_network(self):
        self.ax_network.clear()
        G = nx.DiGraph()
        blockchain = self.blockchain_cli.blockchain
        
        if len(blockchain.chain) <= 1:
            self.ax_network.text(0.5, 0.5, "Only Genesis Block exists!", ha='center', va='center')
            self.canvas_network.draw()
            return
        
        for i, block in enumerate(blockchain.chain):
            G.add_node(i, label=f"Block {block.index}\n{block.validator}")
            if i > 0:
                G.add_edge(i-1, i)
        
        pos = nx.spring_layout(G)
        
        # Draw the graph
        nx.draw_networkx_nodes(G, pos, ax=self.ax_network, node_size=2000, 
                              node_color='skyblue', alpha=0.8)
        nx.draw_networkx_edges(G, pos, ax=self.ax_network, edge_color='black', 
                              arrowsize=20, width=2, alpha=0.7)
        
        # Add labels
        labels = {node: data['label'] for node, data in G.nodes(data=True)}
        nx.draw_networkx_labels(G, pos, labels=labels, ax=self.ax_network,
                               font_size=10, font_weight='bold')
        
        self.ax_network.set_title("Blockchain Structure")
        self.ax_network.axis('off')
        
        self.canvas_network.draw()
    
    def update_log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.update_dashboard()
        
        self.update_visualizations()
    
    def update_dashboard(self):
        self.lbl_total_blocks.config(text=str(len(self.blockchain_cli.blockchain.chain)))
        self.lbl_pending_tx.config(text=str(len(self.blockchain_cli.blockchain.pending_transactions)))
        self.lbl_validators.config(text=str(len(self.blockchain_cli.blockchain.validators)))
        
        self.update_tx_list()
        self.update_validators_list()
        self.update_blocks_list()
    
    def update_tx_list(self):
        self.tx_listbox.delete(0, tk.END)
        
        validator_addresses = list(self.blockchain_cli.blockchain.validators.keys())
        self.cmb_tx_sender['values'] = validator_addresses
        self.cmb_tx_recipient['values'] = validator_addresses
        
        for i, tx in enumerate(self.blockchain_cli.blockchain.pending_transactions):
            self.tx_listbox.insert(tk.END, f"{i+1}. {tx.sender} -> {tx.recipient}: {tx.amount}")
    
    def update_validators_list(self):
        self.validators_listbox.delete(0, tk.END)
        for addr, validator in self.blockchain_cli.blockchain.validators.items():
            self.validators_listbox.insert(tk.END, f"{addr}: {validator.stake} stake")
    
    def update_blocks_list(self):
        self.blocks_listbox.delete(0, tk.END)
        for block in self.blockchain_cli.blockchain.chain:
            self.blocks_listbox.insert(tk.END, f"Block #{block.index} - Validator: {block.validator} - Transactions: {len(block.transactions)}")
    
    def create_transaction(self):
        sender = self.cmb_tx_sender.get()
        recipient = self.cmb_tx_recipient.get()
        amount = self.entry_tx_amount.get()
        
        try:
            amount = float(amount)
            tx = self.blockchain_cli.create_transaction(sender, recipient, amount)
            if tx:
                self.update_log(f"Created transaction: {sender} -> {recipient}: {amount}")
                self.update_tx_list()
        except ValueError:
            self.update_log("Error: Amount must be a number")
    
    def add_validator(self):
        address = self.entry_validator_addr.get()
        stake = self.entry_validator_stake.get()
        
        try:
            stake = float(stake)
            self.blockchain_cli.create_user(address, stake)
            self.update_log(f"Added validator {address} with stake {stake}")
            self.update_validators_list()
            self.update_visualizations()
        except ValueError:
            self.update_log("Error: Stake must be a number")
    
    def get_block_info(self):
        try:
            index = int(self.entry_block_index.get())
            block_info = self.blockchain_cli.get_block_info(index)
            self.block_details_text.delete(1.0, tk.END)
            self.block_details_text.insert(tk.END, block_info)
        except ValueError:
            self.update_log("Error: Block index must be a number")
    
    def export_blockchain(self):
        filename = f"blockchain_export_{int(time.time())}.json"
        self.blockchain_cli.blockchain.save_to_file(filename)
        self.update_log(f"Blockchain exported to {filename}")

class BlockchainVisualizer:
    # additional class for advanced visualizations
    
    @staticmethod
    def create_block_timeline(blockchain, figsize=(10, 6)):
        fig, ax = plt.subplots(figsize=figsize)
        
        block_times = []
        block_indices = []
        validators = []
        colors = {}
        color_map = plt.cm.tab10
        
        for i, block in enumerate(blockchain.chain):
            block_time = datetime.datetime.fromtimestamp(block.timestamp)
            block_times.append(block_time)
            block_indices.append(block.index)
            validators.append(block.validator)
            
            if block.validator not in colors:
                colors[block.validator] = color_map(len(colors) % 10)
        
        for i, (time, index, validator) in enumerate(zip(block_times, block_indices, validators)):
            ax.scatter(time, index, s=100, color=colors[validator], label=validator if validator not in ax.get_legend_handles_labels()[1] else "")
        
        ax.plot(block_times, block_indices, 'k-', alpha=0.3)
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Block Index')
        ax.set_title('Blockchain Timeline')
        
        handles, labels = ax.get_legend_handles_labels()
        by_label = dict(zip(labels, handles))
        ax.legend(by_label.values(), by_label.keys(), title='Validators')
        
        plt.tight_layout()
        return fig
    
    @staticmethod
    def create_transaction_heatmap(blockchain, figsize=(10, 8)):
        all_addresses = set()
        transactions_count = {}
        
        for block in blockchain.chain:
            for tx in block.transactions:
                all_addresses.add(tx.sender)
                all_addresses.add(tx.recipient)
                
                key = (tx.sender, tx.recipient)
                if key in transactions_count:
                    transactions_count[key] += 1
                else:
                    transactions_count[key] = 1
        
        if None in all_addresses:
            all_addresses.remove(None)
        
        addresses = sorted(list(all_addresses))
        n = len(addresses)
        
        if n == 0:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, "No transactions between addresses yet", 
                    ha='center', va='center', fontsize=14)
            ax.axis('off')
            return fig
        
        matrix = np.zeros((n, n))
        
        for (sender, recipient), count in transactions_count.items():
            if sender in addresses and recipient in addresses:
                i = addresses.index(sender)
                j = addresses.index(recipient)
                matrix[i, j] = count
    
        fig, ax = plt.subplots(figsize=figsize)
        im = ax.imshow(matrix, cmap='viridis')
        
        cbar = ax.figure.colorbar(im, ax=ax)
        cbar.ax.set_ylabel("Number of Transactions", rotation=-90, va="bottom")
        
        ax.set_xticks(np.arange(n))
        ax.set_yticks(np.arange(n))
        ax.set_xticklabels(addresses)
        ax.set_yticklabels(addresses)
        
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        
        ax.set_title("Transaction Heatmap Between Addresses")
        ax.set_xlabel("Recipient")
        ax.set_ylabel("Sender")
    
        for i in range(n):
            for j in range(n):
                if matrix[i, j] > 0:
                    ax.text(j, i, int(matrix[i, j]), ha="center", va="center", color="w")
        
        fig.tight_layout()
        return fig
    
    @staticmethod
    def create_stake_history_chart(blockchain_history, figsize=(10, 6)):
        if not blockchain_history:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, "No stake history data available", 
                    ha='center', va='center', fontsize=14)
            ax.axis('off')
            return fig
        
        timestamps = [datetime.datetime.fromtimestamp(ts) for ts, _ in blockchain_history]
        all_validators = set()
        for _, stakes in blockchain_history:
            all_validators.update(stakes.keys())
        
        fig, ax = plt.subplots(figsize=figsize)
        
        for validator in all_validators:
            stakes = []
            for _, validator_stakes in blockchain_history:
                stakes.append(validator_stakes.get(validator, 0))
            ax.plot(timestamps, stakes, marker='o', label=validator)
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Stake')
        ax.set_title('Validator Stake History')
        ax.legend(title='Validators')
        ax.grid(True, linestyle='--', alpha=0.7)
        
        fig.tight_layout()
        return fig

def main():
    choice = input("Choose interface (1 for CLI, 2 for GUI): ")
    
    if choice == "2":
        # check if matplotlib and networkx are available
        try:
            import matplotlib
            import networkx
            root = tk.Tk()
            app = BlockchainGUI(root)
            root.mainloop()
        except ImportError:
            print("Visualization libraries not available. Please install matplotlib and networkx.")
            print("Run: pip install matplotlib networkx")
            cli = BlockchainCLI()
            cli.run()
    elif choice == "1":
        cli = BlockchainCLI()
        cli.run()
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
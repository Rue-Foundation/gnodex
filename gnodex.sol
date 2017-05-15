pragma solidity ^0.4.10;

contract HonestOffChainGNODEX {
    // Data structures
    struct BalanceSheet {
        uint[2] tokenDeposits;
        uint[2] tokenBalance;
        uint[2] tokenWithdrawals;
        bytes32 lastUpdateHash;
        
        uint[2] pendingUpdateBalance;
        bytes32 pendingUpdateHash;
        uint pendingUpdateBlock;
        bool pendingUpdateIsWithdrawal;
        
        bool challenged;
        address challenger;
    }
    
    struct RoundCommitment {
        bytes32 batchMerkleRoot;
        bytes32 routesMerkleRoot;
        bytes32 balanceDeltasMerkleRoot;
        bool challenged;
        bool verified;
    }
    
    
    // State variables
    mapping (address => BalanceSheet) userBalanceSheets;
    RoundCommitment[] roundCommitments;
    
    
    
    // Deposits
    function deposit() payable {
        userBalanceSheets[msg.sender].tokenDeposits[1] += msg.value;
    }
    
    
    
    // State updates
    function queueBalanceUpdate(uint[2] balance, bytes32 hash) {
        var sheet = userBalanceSheets[msg.sender];
        if (sheet.pendingUpdateBlock != 0)
            throw;
        sheet.pendingUpdateBalance = balance;
        sheet.pendingUpdateHash = hash;
        sheet.pendingUpdateBlock = block.number;
        sheet.pendingUpdateIsWithdrawal = false;
    }
    
    function challengeBalanceUpdate(address user) {
        var sheet = userBalanceSheets[user];
        if (sheet.pendingUpdateBlock == 0 || sheet.challenged)
            throw;
        
        sheet.challenged = true;
        sheet.challenger = msg.sender;
    }
    
    function justifyBalanceUpdate(
            bytes32[] merkleProof,
            bool[] markleChainLinkLeft,
            int[] balanceDeltas) {
        var sheet = userBalanceSheets[msg.sender];
        if (!sheet.challenged)
            throw;
        
        var n = balanceDeltas.length;
        int[2] memory delta;
        bytes32 runningHash = sheet.lastUpdateHash;
        for (uint i = 0; 2*i < n; i++) {
            int[2] memory buff;
            buff[0] = balanceDeltas[2*i];
            buff[1] = balanceDeltas[2*i + 1];

            delta[0] += buff[0];
            delta[1] += buff[1];
            
            runningHash = sha3(runningHash, sha3(buff));
        }
        
        assert(sheet.pendingUpdateHash == runningHash);
        assert(sheet.pendingUpdateBalance[0] == uint(int(sheet.tokenBalance[0]) + delta[0]));
        assert(sheet.pendingUpdateBalance[1] == uint(int(sheet.tokenBalance[1]) + delta[1]));
        
        bytes32 merkleRoot = roundCommitments[roundCommitments.length-1].balanceDeltasMerkleRoot;
        
        for (i = 0; i < merkleProof.length; i++) {
            if (merkleProof[i] == merkleRoot)
                break;
            runningHash = markleChainLinkLeft[i] ? sha3(merkleProof[i], runningHash) : sha3(runningHash, merkleProof[i]);
        }
        assert(runningHash == merkleRoot);
        
        sheet.challenged = false;
    }
    
    function enforceBalanceUpdate() {
        var sheet = userBalanceSheets[msg.sender];
        
        assert(!sheet.challenged);
        assert(sheet.pendingUpdateBlock > 0);
        assert(block.number - sheet.pendingUpdateBlock > 10);

        sheet.tokenBalance = sheet.pendingUpdateBalance;
        sheet.lastUpdateHash = sheet.pendingUpdateHash;
        
        sheet.pendingUpdateBalance[0] = 0;
        sheet.pendingUpdateBalance[1] = 0;
        sheet.pendingUpdateHash = 0;
        sheet.pendingUpdateBlock = 0;
        
    }
    
    
    
    // Withdrawal
    function queueWithdrawal(uint[2] amount) {
        var sheet = userBalanceSheets[msg.sender];
        if (sheet.challenged || sheet.pendingUpdateBlock != 0)
            throw;
            
        assert(sheet.tokenDeposits[0] + sheet.tokenBalance[0] - sheet.tokenWithdrawals[0] >= amount[0]);
        assert(sheet.tokenDeposits[1] + sheet.tokenBalance[1] - sheet.tokenWithdrawals[1] >= amount[1]);

        sheet.pendingUpdateBalance = amount;
        sheet.pendingUpdateBlock = block.number;
        sheet.pendingUpdateIsWithdrawal = true;
    }
   
   function challengeWithdrawal(
            address user,
            bytes32[] merkleProof,
            bool[] markleChainLinkLeft,
            int[] delta) {
        var sheet = userBalanceSheets[msg.sender];
        if (sheet.pendingUpdateBlock == 0 || sheet.challenged)
            throw;
            
        bytes32 runningHash = sha3(sheet.lastUpdateHash, sha3(delta));
        bytes32 merkleRoot = roundCommitments[roundCommitments.length-1].balanceDeltasMerkleRoot;
        
        for (uint i = 0; i < merkleProof.length; i++) {
            if (merkleProof[i] == merkleRoot)
                break;
            runningHash = markleChainLinkLeft[i] ? sha3(merkleProof[i], runningHash) : sha3(runningHash, merkleProof[i]);
        }
        assert(runningHash == merkleRoot);
        
        sheet.challenged = true;
        sheet.challenger = msg.sender;
    }
    
    function enforceWithdrawal() {
        var sheet = userBalanceSheets[msg.sender];
        
        assert(!sheet.challenged);
        assert(sheet.pendingUpdateBlock > 0);
        assert(block.number - sheet.pendingUpdateBlock > 10);

    }
    
    
    
    // State update challenges
}

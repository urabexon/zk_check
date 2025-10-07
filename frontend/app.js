class ZKAuthDemo {
    constructor() {
        this.proof = null;
        this.publicSignals = null;
        this.initializeElements();
        this.bindEvents();
    }

    initializeElements() {
        this.passwordInput = document.getElementById('password');
        this.expectedHashInput = document.getElementById('expectedHash');
        this.generateHashBtn = document.getElementById('generateHash');
        this.generateProofBtn = document.getElementById('generateProof');
        this.verifyProofBtn = document.getElementById('verifyProof');
        this.statusDiv = document.getElementById('status');
        this.proofSection = document.getElementById('proofSection');
        this.proofOutput = document.getElementById('proofOutput');
    }

    bindEvents() {
        this.generateHashBtn.addEventListener('click', () => this.generateHash());
        this.generateProofBtn.addEventListener('click', () => this.generateProof());
        this.verifyProofBtn.addEventListener('click', () => this.verifyProof());
    }

    showStatus(message, type = 'info') {
        this.statusDiv.innerHTML = `<div class="status ${type}">${message}</div>`;
    }

    async poseidonHash(input) {
        try {
            const poseidon = window.poseidon || await import('circomlib/src/poseidon.js');
            const hash = poseidon([BigInt(input)]);
            return hash.toString();
        } catch (error) {
            const simpleHash = BigInt('0x' + Array.from(new TextEncoder().encode(input.toString()))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')) % BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
            return simpleHash.toString();
        }
    }

    async generateHash() {
        const password = this.passwordInput.value;
        if (!password) {
            this.showStatus('パスワードを入力してください', 'error');
            return;
        }

        try {
            this.showStatus('ハッシュを計算中...', 'info');
            
            const passwordInt = this.stringToFieldElement(password);
            const hash = await this.poseidonHash(passwordInt);
            
            this.expectedHashInput.value = hash;
            this.showStatus('ハッシュが生成されました', 'success');
        } catch (error) {
            console.error('Hash generation error:', error);
            this.showStatus('ハッシュ生成に失敗しました: ' + error.message, 'error');
        }
    }

    stringToFieldElement(str) {
        const bytes = new TextEncoder().encode(str);
        let result = 0n;
        for (let i = 0; i < Math.min(bytes.length, 31); i++) {
            result = result * 256n + BigInt(bytes[i]);
        }
        return result.toString();
    }

    async generateProof() {
        const password = this.passwordInput.value;
        const expectedHash = this.expectedHashInput.value;

        if (!password || !expectedHash) {
            this.showStatus('パスワードと期待するハッシュ値を入力してください', 'error');
            return;
        }

        try {
            this.showStatus('証明を生成中... (これには時間がかかる場合があります)', 'info');
            this.generateProofBtn.disabled = true;

            const passwordInt = this.stringToFieldElement(password);

            const input = {
                password: passwordInt,
                expectedHash: expectedHash
            };

            const wasmPath = '../build/auth_js/auth.wasm';
            const zkeyPath = '../build/auth_final.zkey';

            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                wasmPath,
                zkeyPath
            );

            this.proof = proof;
            this.publicSignals = publicSignals;

            this.proofOutput.value = JSON.stringify({
                proof: this.proof,
                publicSignals: this.publicSignals
            }, null, 2);

            this.proofSection.style.display = 'block';
            this.verifyProofBtn.disabled = false;
            
            this.showStatus('証明が正常に生成されました！', 'success');
        } catch (error) {
            console.error('Proof generation error:', error);
            this.showStatus('証明生成に失敗しました: ' + error.message, 'error');
        } finally {
            this.generateProofBtn.disabled = false;
        }
    }

    async verifyProof() {
        if (!this.proof || !this.publicSignals) {
            this.showStatus('まず証明を生成してください', 'error');
            return;
        }

        try {
            this.showStatus('証明を検証中...', 'info');
            this.verifyProofBtn.disabled = true;

            const vkeyPath = '../build/verification_key.json';
            const vKey = await fetch(vkeyPath).then(r => r.json());

            const res = await snarkjs.groth16.verify(
                vKey,
                this.publicSignals,
                this.proof
            );

            if (res) {
                this.showStatus('✅ 証明が有効です！認証が成功しました。', 'success');
            } else {
                this.showStatus('❌ 証明が無効です。認証に失敗しました。', 'error');
            }
        } catch (error) {
            console.error('Verification error:', error);
            this.showStatus('証明検証に失敗しました: ' + error.message, 'error');
        } finally {
            this.verifyProofBtn.disabled = false;
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new ZKAuthDemo();
});
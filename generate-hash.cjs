// backend/generate-hash.js

const bcrypt = require('bcryptjs');

const password = 'iniciar';
const saltRounds = 10;

console.log('Gerando hash para a senha:', password);

bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) {
        console.error("Erro ao gerar o hash:", err);
        return;
    }
    console.log("\n============================================================");
    console.log("SEU NOVO HASH GERADO É:");
    console.log(hash);
    console.log("============================================================");
    console.log("\nCopie a linha de cima e cole no seu arquivo server.js");
});
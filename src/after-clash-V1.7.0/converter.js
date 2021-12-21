module.exports.parse = async (raw, { axios, yaml, notify, console, homeDir }, { name, url, interval, selected, mode }) => {
    return tryClash(raw);
    function tryClash(raw){
        try{
            let obj = yaml.parse(raw);
            if (obj.constructor !== Object){
                throw new Error('It seems that the subscription is not in clash form...');
            } else {
                if (obj['Proxy'] && !obj['proxies']){
                    obj['proxies'] = obj['Proxy'];
                    delete obj['Proxy'];
                }
                console.log(obj.proxies.length);
                for (let i = obj.proxies.length; i--;){
                    if (obj.proxies[i].network === 'ws'){
                        if (!('ws-opts' in obj.proxies[i])) {
                            let tmp = {};
                            tmp.headers = {};
                            tmp.headers['Host'] = 'ws-headers' in obj['proxies'][i]?obj['proxies'][i]['ws-headers']['Host']:obj.proxies[i].server;
                            tmp.path = obj['proxies'][i]['ws-path']||'';
                            obj.proxies[i]['ws-opts'] = tmp;
                            delete obj.proxies[i]['ws-headers'];
                            delete obj.proxies[i]['ws-path'];
                        }
                    }
                }
            }
            return yaml.stringify(obj);
        }catch(e){
            console.log(e.name + ' occurs.\n' + e.message + '\nParser trying to parse the content to clash profile.')
            try{
                let tmpproxies = parseB64Sub(raw);
                let obj = {};
                obj['proxies'] = tmpproxies;
                return yaml.stringify(obj);
            }catch(e){
                console.log(e.name + ' occurs.\n' + e.message + '\nParse failed. Please check your subscription.')
                return 'proxies: []';
            }
        }
    }
    function b64DecodeUnicode(str) {
        if (str.length === 0){
            return '';
        }
        let buf = new Buffer(str, 'base64');
        return buf.toString('utf8');
    }
    function parseB64Sub(raw){
        let newProxies = [];
        let rawStr = raw.trim();
        if (!!rawStr.match(/^(ssd:\/\/)/)){
            // ssd subscription matched.
            let str = rawStr.substring(rawStr.indexOf(":") + 3, rawStr.length).trim();
            addSSD(str, newProxies);
        }else{
            let b64Content = b64DecodeUnicode(rawStr);
            let b64Array = b64Content.split('\n');
            for (let [k,v] of b64Array.entries()){
                let type = v.substring(0, v.indexOf(':'));
                let info = v.substring(v.indexOf(':') + 3);
                addNode(type, info, newProxies, k);
            }
        }
        return newProxies;
    }
    function addNode(type, info, target, index){
        switch(type){
            case 'vmess':
                addVmess(info, index, target);
                break;
            case 'ssr':
                addSSR(info, index, target);
                break;
            case 'ss':
                addSS(info, index, target);
                break;
            case 'trojan':
                addTrojan(info, index, target);
                break;
            case 'socks':
                addSocks(info, index, target);
                break;
            case 'http':
                addHttp(info, index, target);
                break;
            default:
                return;
        }
    }
    function addVmess(info, index, target){
        let jsonStr = b64DecodeUnicode(info.trim());
        let jsonNode = JSON.parse(jsonStr);
        let node = {};
        node['name'] = nameNode(jsonNode, index, 'vmess');
        node['type'] = 'vmess';
        node['server'] = jsonNode['add'];
        node['port'] = parseInt(jsonNode['port']);
        node['uuid'] = jsonNode['id'];
        node['alterId'] = parseInt(jsonNode['aid']);
        node['cipher'] = jsonNode['scy']||'auto';
        if (jsonNode['net'] === 'tcp'){
            //skipped
        }else if(jsonNode['net'] === 'ws'){
            node['network'] = 'ws';
            if (typeof jsonNode['host'] !== 'undefined'){
                let tmp = {};
                tmp['headers'] = {};
                tmp['headers']['Host'] = jsonNode['host'];
                tmp['path'] = jsonNode['path'];
                node['ws-opts'] = tmp;
                // The two below are for old versions before Clash releases v1.7.0 (Premium Release 2021.09.07), when Clash decided to change its  format for Vmess proxies. The old configuration is backward compatible to 2022.
                node['ws-headers'] = {};
                node['ws-headers']['Host'] = jsonNode['host'];
                node['ws-path'] = jsonNode['path'];
            }
        }else if(jsonNode['net'] === 'h2'){
            node['network'] = 'h2';
            node['tls'] = true;
            if (typeof jsonNode['host'] !== 'undefined'){
                let tmp = {};
                tmp['path'] = jsonNode['path'];
                tmp['host'] = jsonNode['host'].trim().split(',');
                node['h2-opts'] = tmp;
            }
        }
        if(jsonNode['tls'] === 'tls'){
            node['tls'] = true;
        }
        target.push(node);
    }
    function addSS(info, index, target){
        let node = {};
        let str = info.trim();
        node['name'] = (index + 1).toString() + ' SS ' + decodeURIComponent(str.substring(str.lastIndexOf('#')||str.length, str.length));
        node['type'] = 'ss';
        let serverInfo = str.substring(str.indexOf('@') + 1, str.indexOf('/'));
        node['server'] = serverInfo.substring(0, serverInfo.indexOf(':'));
        node['port'] = parseInt(serverInfo.substring(serverInfo.indexOf(':') + 1));
        let options = b64DecodeUnicode(str.substring(0, str.indexOf('@')));
        node['cipher'] = options.substring(0, options.indexOf(':'));
        node['password'] = options.substring(options.indexOf(':') + 1);
        target.push(node);
    }
    function addSSR(info, index, target){
        let str = b64DecodeUnicode(info);
        let node = {};
        let serverInfo = str.substring(0, str.lastIndexOf('/'));
        let serverInfoArr = serverInfo.split(':');
        node['type'] = 'ssr';
        let i = serverInfoArr.length;
        i--;
        node['password'] = b64DecodeUnicode(serverInfoArr[i]);
        i--;
        node['obfs'] = serverInfoArr[i];
        i--;
        node['cipher'] = serverInfoArr[i];
        i--;
        node['protocol'] = serverInfoArr[i];
        i--;
        node['port'] = parseInt(serverInfoArr[i]);
        if (i !== 1){
            for (let j = 0; j < i; j++){
                node['server'] += serverInfoArr[i] + ':';
            }
            node['server'] = node['server'].substring(0, node['server'].length - 1);
        }else{
            node['server'] = serverInfoArr[0];
        }
        let optionsStr = str.substring(str.indexOf('/') + 2);
        let optionsArr = optionsStr.split('&');
        for (let i of optionsArr){
            let option = i.substring(0, i.indexOf('='));
            let value = b64DecodeUnicode(i.substring(i.indexOf('=') + 1, i.length));
            switch(option){
                case 'obfsparam':
                    if(!!value) {
                        node['obfs-param'] = value;
                    }
                case 'protoparam':
                    if(!!value){
                        node['protocol-param'] = value;
                    }
                    break;
                case 'remarks':
                    node['name'] = (index + 1).toString() + ' SSR ' + value;
                default:
                    break;
            }
        }
        target.push(node);
    }
    function addHttp(info, index, target){
        let str = info.trim();
        let serverInfoStr = str.substring(0, str.indexOf('@') - 1);
        let serverInfoArr = serverInfoStr.split(':');
        let node = {};
        node['name'] = (info + 1).toString() + ' Http';
        node['type'] = 'http';
        node['port'] = parseInt(serverInfoArr[serverInfoArr.length - 1]);
        if(serverInfoArr.length !== 2){
            for (let i = 0; i < serverInfoArr.length - 1; i++){
                node['server'] = node['server'] += serverInfoArr[i] + ':';
            }
            node['server'] = node['server'].substring(0, node['server'].length - 1);
        }else{
            node['server'] = serverInfoArr[0];
        }
        target.push(node);
    }
    function addSocks(info, index, target){
        let str = info.trim();
        let serverInfoStr = str.substring(0, str.indexOf('@') - 1);
        let serverInfoArr = serverInfoStr.split(':');
        let node = {};
        node['name'] = (info + 1).toString() + ' Socks5';
        node['type'] = 'socks5';
        node['port'] = parseInt(serverInfoArr[serverInfoArr.length - 1]);
        if(serverInfoArr.length !== 2){
            for (let i = 0; i < serverInfoArr.length - 1; i++){
                node['server'] = node['server'] += serverInfoArr[i] + ':';
            }
            node['server'] = node['server'].substring(0, node['server'].length - 1);
        }else{
            node['server'] = serverInfoArr[0];
        }
        target.push(node);
    }
    function addTrojan(info, index, target){
        let str = info.trim();
        let node = {};
        node['name'] = (index + 1).toString() + ' Trojan ' + decodeURIComponent(str.lastIndexOf('#') != -1?str.substring(str.lastIndexOf('#') + 1):'');
        node['type'] = 'trojan';
        node['password'] = str.substring(0, str.indexOf('@'));
        let serverInfoStr = str.substring(str.indexOf('@') + 1, str.indexOf('?'));
        let serverInfoArr = serverInfoStr.split(':');
        let i = serverInfoArr.length - 1;
        node['port'] = parseInt(serverInfoArr[i]);
        if (i !== 1){
            for (let j = 0; j < i; j++){
                node['server'] += serverInfoArr[i] + ':';
            }
            node['server'] = node['server'].substring(0, node['server'].length - 1);
        }else{
            node['server'] = serverInfoArr[0];
        }
        let optionsStr = str.substring(str.indexOf('?') + 1, str.lastIndexOf('#'));
        let optionsArr = optionsStr.split('&');
        for (let i of optionsArr){
            let option = i.substring(0, i.indexOf('='));
            let value = i.substring(i.indexOf('=') + 1);
            switch(option){
                case 'sni':
                    node['sni'] = value;
                    break;
                case 'peer':
                    node['sni'] = value;
                    break;
                case 'allowInsecureCertificate':
                    node['skip-cert-verify'] = !!value;
                    break;
                case 'allowInsecure':
                    node['skip-cert-verify'] = !!value;
                    break;
                default:
                    break;
            }
            node['udp'] = true;
        }
        target.push(node);
    }
    function addSSD(str, target){
        let ssdInfo = JSON.parse(b64DecodeUnicode(str));
        let server = ssdInfo['servers'];
        for (let [k,v] of server){
            let node = {};
            node['name'] = v['remarks'];
            node['type'] = 'ss';
            node['server'] = v['server'];
            node['port'] = parseInt(v['port']);
            node['cipher'] = v['encryption'];
            node['password'] = v['password']
            target.push(node);
        }
    }
    function nameNode(info, index, type){
        switch(type){
            case 'vmess':
                let str;
                if(info['ps'] !== ''){
                    str = info['ps']
                }
                return (index + 1).toString() + '_Vmess_' + info['net'] + ' ' + str;
            default:
                return (index + 1).toString() + type.substring(0,1).toUpperCase + type.substring(1);
        }
    }
}

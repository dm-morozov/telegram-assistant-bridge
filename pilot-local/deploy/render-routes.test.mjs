import test from 'node:test';
import assert from 'node:assert/strict';
import { renderSyntheticRoutes } from './render-routes.mjs';
const expectedContainerId='a'.repeat(64),expectedImageId='sha256:'+'b'.repeat(64);
const container={containerId:expectedContainerId,imageId:expectedImageId,project:'telegram-assistant-bridge-synthetic',service:'bridge',running:true,networkCount:1,publishedPortCount:0,internal:true,driver:'bridge',gatewayMode:'nat',ip:'172.30.0.2'};
const request={container,expectedContainerId,expectedImageId,resource:'https://resource.invalid/private-mcp'};
test('synthetic routes expose only protected MCP and public PRM through verified internal IP',()=>{
 const routes=renderSyntheticRoutes(request);assert.match(routes.loopback,/listen 127\.0\.0\.1:18085/);assert.match(routes.loopback,/proxy_pass http:\/\/172\.30\.0\.2:3000/);
 for(const config of Object.values(routes)){assert.match(config,/location = \/private-mcp/);assert.match(config,/location = \/\.well-known\/oauth-protected-resource\/private-mcp/);assert.doesNotMatch(config,/location = \/mcp/);assert.match(config,/X-Forwarded-Proto ""/);assert.match(config,/if \(\$http_origin != ""\)/);assert.match(config,/access_log off/);assert.match(config,/location \/ \{ return 404; \}/);}
});
test('stale/neighbor/published/external/isolated identities and config injection are rejected',()=>{
 for(const patch of [{containerId:'c'.repeat(64)},{imageId:'sha256:'+'d'.repeat(64)},{project:'neighbor'},{service:'other'},{running:false},{networkCount:2},{publishedPortCount:1},{internal:false},{gatewayMode:'isolated'},{ip:'172.30.0.2;bad'},{ip:'127.0.0.1'}])assert.throws(()=>renderSyntheticRoutes({...request,container:{...container,...patch}}));
 for(const resource of ['http://resource.invalid/private-mcp','https://resource.invalid/private-mcp?token=x','https://resource.invalid:8443/private-mcp','https://resource.invalid/path;bad','https://user:pass@resource.invalid/private-mcp'])assert.throws(()=>renderSyntheticRoutes({...request,resource}));
});

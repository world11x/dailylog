// Minimal IndexedDB helper (no external libs)
(function(){
  const DB_NAME = 'daily_log_db';
  const DB_VER = 1;

  const STORES = {
    incidents: { keyPath: 'id' },
    silent: { keyPath: 'id' },
    settings: { keyPath: 'key' },
  };

  function openDB(){
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VER);
      req.onupgradeneeded = () => {
        const db = req.result;
        for (const [name, spec] of Object.entries(STORES)){
          if (!db.objectStoreNames.contains(name)){
            db.createObjectStore(name, spec);
          }
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function tx(storeName, mode, fn){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeName, mode);
      const store = t.objectStore(storeName);
      const result = fn(store);
      t.oncomplete = () => resolve(result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  }

  async function get(store, key){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, 'readonly');
      const s = t.objectStore(store);
      const r = s.get(key);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  async function put(store, val){
    return tx(store, 'readwrite', s => s.put(val));
  }

  async function del(store, key){
    return tx(store, 'readwrite', s => s.delete(key));
  }

  async function getAll(store){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, 'readonly');
      const s = t.objectStore(store);
      const r = s.getAll();
      r.onsuccess = () => resolve(r.result || []);
      r.onerror = () => reject(r.error);
    });
  }

  async function clearStore(store){
    return tx(store, 'readwrite', s => s.clear());
  }

  async function resetAll(){
    const db = await openDB();
    db.close();
    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('DB delete blocked'));
    });
  }

  window.IDBStore = { openDB, get, put, del, getAll, clearStore, resetAll, DB_NAME };
})();

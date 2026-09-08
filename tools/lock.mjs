#!/usr/bin/env node
/**
 * Збирає index.html: шифрує вміст каталогу паролем і вбудовує шифротекст
 * у сторінку-замок. Плейнтекст каталогу в репозиторій не потрапляє.
 *
 *   node tools/lock.mjs "пароль"
 *
 * Джерело вмісту: _catalog.html (у .gitignore, лише локально).
 * Результат:      index.html
 *
 * Криптографія: PBKDF2-HMAC-SHA256, 310 000 ітерацій → AES-256-GCM.
 * Формат сумісний із WebCrypto у браузері (шифротекст || тег автентифікації).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } from 'node:crypto';

const ITER = 310000;
const pass = process.argv[2];
if (!pass) {
  console.error('Вкажіть пароль:  node tools/lock.mjs "пароль"');
  process.exit(1);
}

const plain = readFileSync(new URL('../_catalog.html', import.meta.url), 'utf8');
const tpl   = readFileSync(new URL('./gate.template.html', import.meta.url), 'utf8');

const salt = randomBytes(16);
const iv   = randomBytes(12);
const key  = pbkdf2Sync(pass, salt, ITER, 32, 'sha256');

const c   = createCipheriv('aes-256-gcm', key, iv);
const ct  = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
const tag = c.getAuthTag();
const payload = Buffer.concat([ct, tag]);          // WebCrypto чекає саме такий порядок

// самоперевірка: розшифровуємо назад тим самим ключем
const d = createDecipheriv('aes-256-gcm', key, iv);
d.setAuthTag(tag);
const back = Buffer.concat([d.update(ct), d.final()]).toString('utf8');
if (back !== plain) { console.error('Помилка: перевірка розшифрування не пройшла'); process.exit(1); }

const out = tpl
  .replace('__SALT__', salt.toString('base64'))
  .replace('__IV__', iv.toString('base64'))
  .replace('__DATA__', payload.toString('base64'))
  .replace('__ITER__', String(ITER));

writeFileSync(new URL('../index.html', import.meta.url), out);

// контроль: у результаті не має лишитись жодного сліду плейнтексту
const leaks = ['Освітня вертикаль', 'Місто як гра', 'gamification/', 'osvita/']
  .filter(w => out.includes(w));
console.log('index.html зібрано.');
console.log('  вміст каталогу:', plain.length, 'символів →', payload.length, 'байт шифротексту');
console.log('  витоки плейнтексту:', leaks.length ? leaks.join(', ') : 'немає');
if (leaks.length) process.exit(1);

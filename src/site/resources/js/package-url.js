/*
Copyright (c) the purl authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
class PackageURL {

  constructor(type, namespace, name, version, qualifiers, subpath) {
    let required = { 'type': type, 'name': name };
    Object.keys(required).forEach(key => {
      if (!required[key]) {
        throw new Error('Invalid purl: "' + key + '" is a required field.');
      }
    });

    let strings = { 'type': type, 'namespace': namespace, 'name': name, 'versions': version, 'subpath': subpath };
    Object.keys(strings).forEach(key => {
      if (strings[key] && typeof strings[key] === 'string' || !strings[key]) {
        return;
      }
      throw new Error('Invalid purl: "' + key + '" argument must be a string.');
    });

    if (qualifiers) {
      if (typeof qualifiers !== 'object') {
        throw new Error('Invalid purl: "qualifiers" argument must be a dictionary.');
      }
      Object.keys(qualifiers).forEach(key => {
        if (!/^[a-z]+$/i.test(key) && !/[\.-_]/.test(key)) {
          throw new Error('Invalid purl: qualifier "' + key + '" contains an illegal character.');
        }
      });
    }

    this.type = type;
    this.name = name;
    this.namespace = namespace;
    this.version = version;
    this.qualifiers = qualifiers;
    this.subpath = subpath;
  }

  toString() {
    var purl = ['pkg:', this.type, '/'];

    if (this.namespace) {
      purl.push(encodeURIComponent(this.namespace).replace('%3A', ':'));
      purl.push('/');
    }

    purl.push(encodeURIComponent(this.name).replace('%3A', ':'));

    if (this.version) {
      purl.push('@');
      purl.push(encodeURIComponent(this.version).replace('%3A', ':'));
    }

    if (this.qualifiers) {
      purl.push('?');

      let qualifiers = this.qualifiers;
      let qualifierString = [];
      Object.keys(qualifiers).sort().forEach(key => {
        qualifierString.push(encodeURIComponent(key).replace('%3A', ':') + '=' + encodeURI(qualifiers[key]));
      });

      purl.push(qualifierString.join('&'));
    }

    if (this.subpath) {
      purl.push('#');
      purl.push(encodeURI(this.subpath));
    }

    return purl.join('');
  }

  static fromString(purl) {
    if (!purl || !typeof purl === 'string' || !purl.trim()) {
      throw new Error('A purl string argument is required.');
    }

    var [scheme, remainder] = purl.split(':');
    if (scheme !== 'pkg') {
      throw new Error('purl is missing the required "pkg" scheme component.');
    }
    // this strip '/, // and /// as possible in :// or :///
    // from https://gist.github.com/refo/47632c8a547f2d9b6517#file-remove-leading-slash
    remainder = remainder.trim().replace(/^\/+/g, '');

    let type = remainder.split('/')[0];
    var remainder = remainder.split('/').slice(1).join('/');
    if (!type || !remainder) {
      throw new Error('purl is missing the required "type" component.');
    }

    let url = new URL(purl);

    let qualifiers = null;
    url.searchParams.forEach((value, key) => {
      if (!qualifiers) {
        qualifiers = {};
      }
      qualifiers[key] = value;
    });
    let subpath = url.hash;
    if (subpath.indexOf('#') === 0) {
      subpath = subpath.substring(1);
    }
    if (subpath.length === 0) {
      subpath = null;
    }

    if (url.username !== '' || url.password !== '') {
      throw new Error('Invalid purl: cannot contain a "user:pass@host:port"');
    }

    // this strip '/, // and /// as possible in :// or :///
    // from https://gist.github.com/refo/47632c8a547f2d9b6517#file-remove-leading-slash
    let path = url.pathname.trim().replace(/^\/+/g, '');

    // version is optional - check for existence
    let version = null;
    if (path.includes('@')) {
      let index = path.indexOf('@');
      version = decodeURIComponent(path.substring(index + 1));
      remainder = path.substring(0, index);
    } else {
      remainder = path;
    }

    // The 'remainder' should now consist of an optional namespace and the name
    let remaining = remainder.split('/').slice(1);
    let name = null;
    let namespace = null;
    if (remaining.length > 1) {
      let nameIndex = remaining.length - 1;
      let namespaceComponents = remaining.slice(0, nameIndex);
      name = decodeURIComponent(remaining[nameIndex]);
      namespace = decodeURIComponent(namespaceComponents.join('/'));
    } else if (remaining.length === 1) {
      name = decodeURIComponent(remaining[0]);
    }

    if (name === '') {
      throw new Error('purl is missing the required "name" component.');
    }

    return new PackageURL(type, namespace, name, version, qualifiers, subpath);
  }

};

module.exports = PackageURL;

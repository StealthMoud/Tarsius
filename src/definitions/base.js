// base finding class - all vulnerabilty definitions extend this
// each defintion describes what a vuln is, how to fix it, and refrences

export class FindingBase {
    // overide these in subclases
    static name() { return ''; }
    static description() { return ''; }
    static references() { return []; }
    static solution() { return ''; }
    static shortName() { return ''; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return []; }
}

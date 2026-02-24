// base vuln defintion class

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

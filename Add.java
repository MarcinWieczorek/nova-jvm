class Add {
    public static void main(String[] args) {
        int a = 123;
        int b = 321;
        int c = add(a, b);
        // Add d = new Add();
        // d.ns_add(a, b);
        System.out.println(c);
    }

    public static int add(int a, int b) {
        return a + b;
    }

    public int ns_add(int a, int b) {
        return a + b;
    }

    public static int test5(int a, int b, int c, int d, int e) {
        int aa = a, bb = b, cc = c, dd = d, ee = e;
        return 0;
    }
}

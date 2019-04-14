class Add {
    public static int field1;

    public static void main(String[] args) {
        testLoop(5);
        //Expect 10
        testAdd();
        //Expect 444
        testStaticField();
        //Expect 12
        testMultipleObjects();
        //Expect 124 4
    }

    public static void testLoop(int max) {
        int a = 0;
        for(int i = 0; i < max; i++) {
            a += i;
        }
        System.out.println(a);
    }

    public static void testAdd() {
        int a = 123;
        int b = 321;
        int c = a + b;
        System.out.println(c);
    }

    public static void testMultipleObjects() {
        B b1 = new B(123);
        B b2 = new B(3);
        b1.inc();
        b2.inc();
        b1.print();
        b2.print();
    }

    public static void testStaticField() {
        int a = 12;
        Add.field1 = a;
        int b = Add.field1;
        System.out.println(b);
    }
}

class B {
    private int v;

    B(int v) {
        this.v = v;
    }

    public void inc() {
        this.v++;
    }

    public void print() {
        System.out.println(this.v);
    }
}

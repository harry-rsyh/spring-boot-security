package com.harry.security.spring.student;

public class Student {

    private final Integer studentId;
    private final String studentNama;

    public Student(Integer studentId, String studentNama) {
        this.studentId = studentId;
        this.studentNama = studentNama;
    }

    public Integer getStudentId() {
        return studentId;
    }

    public String getStudentNama() {
        return studentNama;
    }

}

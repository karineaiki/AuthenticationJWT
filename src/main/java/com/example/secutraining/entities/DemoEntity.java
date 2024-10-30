package com.example.secutraining.entities;

import jakarta.annotation.Nonnull;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "demo")
public class DemoEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    public String id;

    @Nonnull
    @Column(name = "content", nullable = false)
    public String content;

    public DemoEntity() {
    }

    public DemoEntity(String content) {
        this.content = content;
    }

    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getContent() {
        return this.content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @Override
    public String toString() {
        return "{" +
                " id='" + getId() + "'" +
                ", content='" + getContent() + "'" +
                "}";
    }

}

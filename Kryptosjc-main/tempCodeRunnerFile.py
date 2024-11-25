#security question
@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if 'otp_verified' not in session or 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "error")
        return redirect(url_for('recover_password'))

    email = session['reset_email']

    try:
        # Fetch the security question from the database
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT security_question FROM accounts WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            security_question = user['security_question']
        else:
            flash("User not found.", "error")
            return redirect(url_for('recover_password'))
    except Exception as e:
        print(f"Error fetching security question: {e}")
        flash("An error occurred. Please try again.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        security_answer_input = request.form['security_answer']

        try:
            # Fetch the security answer from the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT security_answer FROM accounts WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user:
                security_answer = user['security_answer']

                # Compare the input with the stored answer
                if security_answer_input.lower() == security_answer.lower():
                    session['security_verified'] = True
                    return redirect(url_for('reset_password'))
                else:
                    flash("Incorrect security answer. Please try again.", "error")
                    return redirect(url_for('security_question'))
            else:
                flash("User not found.", "error")
                return redirect(url_for('recover_password'))
        except Exception as e:
            print(f"Error during security answer verification: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('security_question'))

    return render_template('security_question.html', security_question=security_question)